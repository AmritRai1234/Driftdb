//! DriftQL Parser — Recursive descent parser that builds AST from tokens

use driftdb_core::error::{DriftError, DriftResult};
use driftdb_core::types::Value;
use std::collections::HashMap;

use crate::ast::*;
use crate::lexer::Token;

/// Parser state
pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        tok
    }

    fn expect(&mut self, expected: &Token) -> DriftResult<Token> {
        let tok = self.advance();
        if std::mem::discriminant(&tok) == std::mem::discriminant(expected) {
            Ok(tok)
        } else {
            Err(DriftError::InvalidQuery(format!(
                "Expected {:?}, got {:?}",
                expected, tok
            )))
        }
    }

    fn expect_identifier(&mut self) -> DriftResult<String> {
        match self.advance() {
            Token::Identifier(s) => Ok(s),
            other => Err(DriftError::InvalidQuery(format!(
                "Expected identifier, got {:?}",
                other
            ))),
        }
    }

    /// Parse a single statement
    pub fn parse(&mut self) -> DriftResult<Statement> {
        match self.peek().clone() {
            Token::Create => self.parse_create(),
            Token::Link => self.parse_link(),
            Token::Find => self.parse_find(),
            Token::Set => self.parse_set(),
            Token::Delete => self.parse_delete(),
            Token::Show => self.parse_show(),
            Token::Help => { self.advance(); Ok(Statement::Help) }
            _ => Err(DriftError::InvalidQuery(format!(
                "Unexpected token: {:?}. Expected CREATE, LINK, FIND, SET, DELETE, SHOW, or HELP",
                self.peek()
            ))),
        }
    }

    /// Parse: CREATE (var:Label {key: value, ...})
    fn parse_create(&mut self) -> DriftResult<Statement> {
        self.advance(); // consume CREATE
        self.expect(&Token::LeftParen)?;

        let mut variable = None;
        let mut labels = Vec::new();
        let mut properties = HashMap::new();

        // Parse variable name (optional if followed by colon)
        if let Token::Identifier(_) = self.peek() {
            let ident = self.expect_identifier()?;
            if matches!(self.peek(), Token::Colon) {
                // It's var:Label
                variable = Some(ident);
                self.advance(); // consume :
                labels.push(self.expect_identifier()?);
            } else {
                // It's just a label
                labels.push(ident);
            }
        }

        // Parse additional labels
        while matches!(self.peek(), Token::Colon) {
            self.advance();
            labels.push(self.expect_identifier()?);
        }

        // Parse properties
        if matches!(self.peek(), Token::LeftBrace) {
            properties = self.parse_properties()?;
        }

        self.expect(&Token::RightParen)?;

        Ok(Statement::CreateNode {
            variable,
            labels,
            properties,
        })
    }

    /// Parse: LINK (var1)-[:TYPE {props}]->(var2)
    fn parse_link(&mut self) -> DriftResult<Statement> {
        self.advance(); // consume LINK

        // Parse source node ref
        let source = self.parse_node_ref()?;

        // Parse -[:TYPE {props}]->
        self.expect(&Token::Dash)?;
        self.expect(&Token::LeftBracket)?;
        self.expect(&Token::Colon)?;
        let edge_type = self.expect_identifier()?;

        let mut properties = HashMap::new();
        if matches!(self.peek(), Token::LeftBrace) {
            properties = self.parse_properties()?;
        }

        self.expect(&Token::RightBracket)?;
        self.expect(&Token::Arrow)?;

        // Parse target node ref
        let target = self.parse_node_ref()?;

        Ok(Statement::CreateEdge {
            source,
            target,
            edge_type,
            properties,
        })
    }

    /// Parse: FIND pattern WHERE ... RETURN ... AT ...
    fn parse_find(&mut self) -> DriftResult<Statement> {
        self.advance(); // consume FIND

        // Check for SIMILAR TO
        if matches!(self.peek(), Token::SimilarTo) {
            return self.parse_find_similar();
        }

        // Parse pattern
        let pattern = self.parse_pattern()?;

        // Parse optional AT timestamp
        let mut at_time = None;
        if matches!(self.peek(), Token::At) {
            self.advance();
            match self.advance() {
                Token::StringLiteral(s) => at_time = Some(s),
                other => return Err(DriftError::InvalidQuery(format!(
                    "Expected timestamp string after AT, got {:?}", other
                ))),
            }
        }

        // Parse optional WHERE clause
        let mut where_clause = None;
        if matches!(self.peek(), Token::Where) {
            where_clause = Some(self.parse_where()?);
        }

        // Parse optional RETURN clause
        let mut return_fields = Vec::new();
        if matches!(self.peek(), Token::Return) {
            self.advance();
            return_fields = self.parse_return_fields()?;
        }

        Ok(Statement::Find {
            pattern,
            where_clause,
            return_fields,
            at_time,
        })
    }

    /// Parse: FIND SIMILAR TO [vec] WITHIN threshold
    fn parse_find_similar(&mut self) -> DriftResult<Statement> {
        self.advance(); // consume SIMILAR TO

        // Parse vector literal [f64, f64, ...]
        self.expect(&Token::LeftBracket)?;
        let mut vector = Vec::new();
        loop {
            match self.peek().clone() {
                Token::RightBracket => { self.advance(); break; }
                Token::FloatLiteral(f) => { self.advance(); vector.push(f); }
                Token::IntLiteral(i) => { self.advance(); vector.push(i as f64); }
                Token::Comma => { self.advance(); }
                other => return Err(DriftError::InvalidQuery(format!(
                    "Expected number in vector, got {:?}", other
                ))),
            }
        }

        // Parse WITHIN threshold
        let mut threshold = 0.0;
        if matches!(self.peek(), Token::Within) {
            self.advance();
            match self.advance() {
                Token::FloatLiteral(f) => threshold = f,
                Token::IntLiteral(i) => threshold = i as f64,
                other => return Err(DriftError::InvalidQuery(format!(
                    "Expected number after WITHIN, got {:?}", other
                ))),
            }
        }

        // Parse optional LIMIT
        let mut limit = None;
        if matches!(self.peek(), Token::Limit) {
            self.advance();
            match self.advance() {
                Token::IntLiteral(n) => limit = Some(n as usize),
                other => return Err(DriftError::InvalidQuery(format!(
                    "Expected integer after LIMIT, got {:?}", other
                ))),
            }
        }

        // Parse optional RETURN
        let mut return_fields = Vec::new();
        if matches!(self.peek(), Token::Return) {
            self.advance();
            return_fields = self.parse_return_fields()?;
        }

        Ok(Statement::FindSimilar {
            vector,
            threshold,
            limit,
            return_fields,
        })
    }

    /// Parse a graph pattern: (var:Label)-[:EDGE]->(var:Label)
    fn parse_pattern(&mut self) -> DriftResult<Vec<PatternElement>> {
        let mut elements = Vec::new();

        // Parse first node
        elements.push(self.parse_pattern_node(None)?);

        // Parse subsequent edge-node pairs
        while matches!(self.peek(), Token::Dash) {
            self.advance(); // consume -
            self.expect(&Token::LeftBracket)?;

            // Parse optional edge type
            let edge_type = if matches!(self.peek(), Token::Colon) {
                self.advance();
                Some(self.expect_identifier()?)
            } else {
                None
            };

            self.expect(&Token::RightBracket)?;
            self.expect(&Token::Arrow)?;

            elements.push(self.parse_pattern_node(edge_type)?);
        }

        Ok(elements)
    }

    /// Parse a single node in a pattern: (var:Label {conditions})
    fn parse_pattern_node(&mut self, edge_type: Option<String>) -> DriftResult<PatternElement> {
        self.expect(&Token::LeftParen)?;

        let mut variable = String::new();
        let mut label = None;
        let mut conditions = HashMap::new();

        if let Token::Identifier(_) = self.peek() {
            let ident = self.expect_identifier()?;
            if matches!(self.peek(), Token::Colon) {
                variable = ident;
                self.advance();
                label = Some(self.expect_identifier()?);
            } else {
                variable = ident;
            }
        }

        if matches!(self.peek(), Token::LeftBrace) {
            conditions = self.parse_properties()?;
        }

        self.expect(&Token::RightParen)?;

        Ok(PatternElement {
            variable,
            label,
            edge_type,
            conditions,
        })
    }

    /// Parse a node reference: (var) or (var:Label)
    fn parse_node_ref(&mut self) -> DriftResult<NodeRef> {
        self.expect(&Token::LeftParen)?;

        let variable = self.expect_identifier()?;
        let mut label = None;
        let mut conditions = HashMap::new();

        if matches!(self.peek(), Token::Colon) {
            self.advance();
            label = Some(self.expect_identifier()?);
        }

        if matches!(self.peek(), Token::LeftBrace) {
            conditions = self.parse_properties()?;
        }

        self.expect(&Token::RightParen)?;

        Ok(NodeRef {
            variable,
            label,
            conditions,
        })
    }

    /// Parse: {key: value, key: value}
    fn parse_properties(&mut self) -> DriftResult<HashMap<String, Value>> {
        self.expect(&Token::LeftBrace)?;
        let mut props = HashMap::new();

        while !matches!(self.peek(), Token::RightBrace | Token::Eof) {
            let key = self.expect_identifier()?;
            self.expect(&Token::Colon)?;
            let value = self.parse_value()?;
            props.insert(key, value);

            if matches!(self.peek(), Token::Comma) {
                self.advance();
            }
        }

        self.expect(&Token::RightBrace)?;
        Ok(props)
    }

    /// Parse a value literal
    fn parse_value(&mut self) -> DriftResult<Value> {
        match self.advance() {
            Token::StringLiteral(s) => Ok(Value::String(s)),
            Token::IntLiteral(i) => Ok(Value::Int(i)),
            Token::FloatLiteral(f) => Ok(Value::Float(f)),
            Token::Identifier(s) => match s.to_lowercase().as_str() {
                "true" => Ok(Value::Bool(true)),
                "false" => Ok(Value::Bool(false)),
                "null" => Ok(Value::Null),
                _ => Ok(Value::String(s)),
            },
            Token::LeftBracket => {
                // Parse list or vector
                let mut items = Vec::new();
                let mut is_float_vec = true;
                while !matches!(self.peek(), Token::RightBracket | Token::Eof) {
                    let val = self.parse_value()?;
                    if !matches!(val, Value::Float(_) | Value::Int(_)) {
                        is_float_vec = false;
                    }
                    items.push(val);
                    if matches!(self.peek(), Token::Comma) {
                        self.advance();
                    }
                }
                self.expect(&Token::RightBracket)?;

                if is_float_vec && items.iter().all(|v| matches!(v, Value::Float(_) | Value::Int(_))) {
                    let floats: Vec<f64> = items
                        .iter()
                        .map(|v| match v {
                            Value::Float(f) => *f,
                            Value::Int(i) => *i as f64,
                            _ => 0.0,
                        })
                        .collect();
                    Ok(Value::Vector(floats))
                } else {
                    Ok(Value::List(items))
                }
            }
            other => Err(DriftError::InvalidQuery(format!(
                "Expected value, got {:?}",
                other
            ))),
        }
    }

    /// Parse: WHERE var.prop = value AND var.prop > value
    fn parse_where(&mut self) -> DriftResult<WhereClause> {
        self.advance(); // consume WHERE
        let mut conditions = Vec::new();

        loop {
            let variable = self.expect_identifier()?;
            self.expect(&Token::Dot)?;
            let property = self.expect_identifier()?;

            let operator = match self.advance() {
                Token::Eq => ComparisonOp::Eq,
                Token::Neq => ComparisonOp::Neq,
                Token::Lt => ComparisonOp::Lt,
                Token::Gt => ComparisonOp::Gt,
                Token::Lte => ComparisonOp::Lte,
                Token::Gte => ComparisonOp::Gte,
                other => return Err(DriftError::InvalidQuery(format!(
                    "Expected comparison operator, got {:?}", other
                ))),
            };

            let value = self.parse_value()?;

            conditions.push(Condition {
                variable,
                property,
                operator,
                value,
            });

            // Check for AND
            if let Token::Identifier(ref s) = self.peek() {
                if s.to_uppercase() == "AND" {
                    self.advance();
                    continue;
                }
            }
            break;
        }

        Ok(WhereClause { conditions })
    }

    /// Parse: RETURN var.prop, var.prop, var
    fn parse_return_fields(&mut self) -> DriftResult<Vec<ReturnField>> {
        let mut fields = Vec::new();

        loop {
            let variable = self.expect_identifier()?;
            let property = if matches!(self.peek(), Token::Dot) {
                self.advance();
                Some(self.expect_identifier()?)
            } else {
                None
            };

            fields.push(ReturnField { variable, property });

            if matches!(self.peek(), Token::Comma) {
                self.advance();
            } else {
                break;
            }
        }

        Ok(fields)
    }

    /// Parse: SET var.property = value
    fn parse_set(&mut self) -> DriftResult<Statement> {
        self.advance(); // consume SET
        let var_name = self.expect_identifier()?;
        self.expect(&Token::Dot)?;
        let property = self.expect_identifier()?;
        self.expect(&Token::Eq)?;
        let value = self.parse_value()?;

        Ok(Statement::SetProperty {
            node_ref: NodeRef {
                variable: var_name,
                label: None,
                conditions: HashMap::new(),
            },
            property,
            value,
        })
    }

    /// Parse: DELETE (var)
    fn parse_delete(&mut self) -> DriftResult<Statement> {
        self.advance(); // consume DELETE
        let node_ref = self.parse_node_ref()?;
        Ok(Statement::Delete { node_ref })
    }

    /// Parse: SHOW NODES | SHOW EDGES | SHOW STATS | SHOW EVENTS
    fn parse_show(&mut self) -> DriftResult<Statement> {
        self.advance(); // consume SHOW
        let target = match self.advance() {
            Token::Nodes => ShowTarget::Nodes,
            Token::Edges => ShowTarget::Edges,
            Token::Stats => ShowTarget::Stats,
            Token::Events => ShowTarget::Events,
            other => return Err(DriftError::InvalidQuery(format!(
                "Expected NODES, EDGES, STATS, or EVENTS after SHOW, got {:?}", other
            ))),
        };
        Ok(Statement::Show { target })
    }
}

/// Convenience function to parse a DriftQL string
pub fn parse(input: &str) -> DriftResult<Statement> {
    let tokens = crate::lexer::tokenize(input)?;
    let mut parser = Parser::new(tokens);
    parser.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_create() {
        let stmt = parse("CREATE (u:User {name: \"Amrit\", age: 22})").unwrap();
        match stmt {
            Statement::CreateNode { variable, labels, properties } => {
                assert_eq!(variable, Some("u".to_string()));
                assert_eq!(labels, vec!["User"]);
                assert_eq!(properties.len(), 2);
            }
            _ => panic!("Expected CreateNode"),
        }
    }

    #[test]
    fn test_parse_show() {
        let stmt = parse("SHOW NODES").unwrap();
        assert!(matches!(stmt, Statement::Show { target: ShowTarget::Nodes }));
    }

    #[test]
    fn test_parse_find_simple() {
        let stmt = parse("FIND (u:User) RETURN u.name").unwrap();
        match stmt {
            Statement::Find { pattern, return_fields, .. } => {
                assert_eq!(pattern.len(), 1);
                assert_eq!(return_fields.len(), 1);
                assert_eq!(return_fields[0].variable, "u");
                assert_eq!(return_fields[0].property, Some("name".to_string()));
            }
            _ => panic!("Expected Find"),
        }
    }

    #[test]
    fn test_parse_find_pattern() {
        let stmt = parse("FIND (u:User)-[:LIKES]->(s:Song) RETURN u.name, s.title").unwrap();
        match stmt {
            Statement::Find { pattern, return_fields, .. } => {
                assert_eq!(pattern.len(), 2);
                assert_eq!(pattern[1].edge_type, Some("LIKES".to_string()));
                assert_eq!(return_fields.len(), 2);
            }
            _ => panic!("Expected Find"),
        }
    }

    #[test]
    fn test_parse_link() {
        let stmt = parse("LINK (u)-[:BUILT]->(p)").unwrap();
        match stmt {
            Statement::CreateEdge { source, target, edge_type, .. } => {
                assert_eq!(source.variable, "u");
                assert_eq!(target.variable, "p");
                assert_eq!(edge_type, "BUILT");
            }
            _ => panic!("Expected CreateEdge"),
        }
    }

    #[test]
    fn test_parse_help() {
        let stmt = parse("HELP").unwrap();
        assert!(matches!(stmt, Statement::Help));
    }
}
