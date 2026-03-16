//! DriftQL Lexer — Tokenizes query strings into a token stream

use driftdb_core::error::{DriftError, DriftResult};

/// Token types for DriftQL
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Keywords
    Create,
    Link,
    Find,
    Where,
    Return,
    Set,
    Delete,
    Show,
    At,
    SimilarTo,
    Within,
    Limit,
    Help,

    // Show targets
    Nodes,
    Edges,
    Stats,
    Events,

    // Literals
    Identifier(String),
    StringLiteral(String),
    IntLiteral(i64),
    FloatLiteral(f64),

    // Punctuation
    LeftParen,    // (
    RightParen,   // )
    LeftBracket,  // [
    RightBracket, // ]
    LeftBrace,    // {
    RightBrace,   // }
    Colon,        // :
    Comma,        // ,
    Dot,          // .
    Arrow,        // ->
    Dash,         // -
    Eq,           // =
    Neq,          // !=
    Lt,           // <
    Gt,           // >
    Lte,          // <=
    Gte,          // >=

    // Special
    Eof,
}

/// Tokenize a DriftQL query string
pub fn tokenize(input: &str) -> DriftResult<Vec<Token>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        // Skip whitespace
        if ch.is_whitespace() {
            i += 1;
            continue;
        }

        // Skip comments (-- line comments)
        if ch == '-' && i + 1 < chars.len() && chars[i + 1] == '-'
            && !(i + 2 < chars.len() && chars[i + 2] == '>')
        {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        // Arrow ->
        if ch == '-' && i + 1 < chars.len() && chars[i + 1] == '>' {
            tokens.push(Token::Arrow);
            i += 2;
            continue;
        }

        // Comparison operators
        if ch == '!' && i + 1 < chars.len() && chars[i + 1] == '=' {
            tokens.push(Token::Neq);
            i += 2;
            continue;
        }
        if ch == '<' && i + 1 < chars.len() && chars[i + 1] == '=' {
            tokens.push(Token::Lte);
            i += 2;
            continue;
        }
        if ch == '>' && i + 1 < chars.len() && chars[i + 1] == '=' {
            tokens.push(Token::Gte);
            i += 2;
            continue;
        }

        // Single char tokens
        match ch {
            '(' => { tokens.push(Token::LeftParen); i += 1; continue; }
            ')' => { tokens.push(Token::RightParen); i += 1; continue; }
            '[' => { tokens.push(Token::LeftBracket); i += 1; continue; }
            ']' => { tokens.push(Token::RightBracket); i += 1; continue; }
            '{' => { tokens.push(Token::LeftBrace); i += 1; continue; }
            '}' => { tokens.push(Token::RightBrace); i += 1; continue; }
            ':' => { tokens.push(Token::Colon); i += 1; continue; }
            ',' => { tokens.push(Token::Comma); i += 1; continue; }
            '.' => { tokens.push(Token::Dot); i += 1; continue; }
            '-' => { tokens.push(Token::Dash); i += 1; continue; }
            '=' => { tokens.push(Token::Eq); i += 1; continue; }
            '<' => { tokens.push(Token::Lt); i += 1; continue; }
            '>' => { tokens.push(Token::Gt); i += 1; continue; }
            _ => {}
        }

        // String literals
        if ch == '"' || ch == '\'' {
            let quote = ch;
            i += 1;
            let mut s = String::new();
            while i < chars.len() && chars[i] != quote {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    match chars[i] {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        '\\' => s.push('\\'),
                        c => { s.push('\\'); s.push(c); }
                    }
                } else {
                    s.push(chars[i]);
                }
                i += 1;
            }
            if i >= chars.len() {
                return Err(DriftError::InvalidQuery("Unterminated string literal".into()));
            }
            i += 1; // skip closing quote
            tokens.push(Token::StringLiteral(s));
            continue;
        }

        // Numbers
        if ch.is_ascii_digit() || (ch == '-' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit()) {
            let mut num_str = String::new();
            if ch == '-' {
                num_str.push(ch);
                i += 1;
            }
            let mut is_float = false;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                if chars[i] == '.' {
                    is_float = true;
                }
                num_str.push(chars[i]);
                i += 1;
            }
            if is_float {
                let f: f64 = num_str.parse().map_err(|_| {
                    DriftError::InvalidQuery(format!("Invalid float: {}", num_str))
                })?;
                tokens.push(Token::FloatLiteral(f));
            } else {
                let n: i64 = num_str.parse().map_err(|_| {
                    DriftError::InvalidQuery(format!("Invalid integer: {}", num_str))
                })?;
                tokens.push(Token::IntLiteral(n));
            }
            continue;
        }

        // Identifiers and keywords
        if ch.is_alphabetic() || ch == '_' {
            let mut ident = String::new();
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                ident.push(chars[i]);
                i += 1;
            }

            let token = match ident.to_uppercase().as_str() {
                "CREATE" => Token::Create,
                "LINK" => Token::Link,
                "FIND" => Token::Find,
                "WHERE" => Token::Where,
                "RETURN" => Token::Return,
                "SET" => Token::Set,
                "DELETE" => Token::Delete,
                "SHOW" => Token::Show,
                "AT" => Token::At,
                "SIMILAR" => {
                    // Check for "SIMILAR TO"
                    // Skip whitespace
                    while i < chars.len() && chars[i].is_whitespace() {
                        i += 1;
                    }
                    let mut next = String::new();
                    let save_i = i;
                    while i < chars.len() && chars[i].is_alphabetic() {
                        next.push(chars[i]);
                        i += 1;
                    }
                    if next.to_uppercase() == "TO" {
                        Token::SimilarTo
                    } else {
                        i = save_i;
                        Token::Identifier(ident)
                    }
                }
                "WITHIN" => Token::Within,
                "LIMIT" => Token::Limit,
                "NODES" => Token::Nodes,
                "EDGES" => Token::Edges,
                "STATS" => Token::Stats,
                "EVENTS" => Token::Events,
                "HELP" => Token::Help,
                "TRUE" | "FALSE" => Token::Identifier(ident),
                _ => Token::Identifier(ident),
            };
            tokens.push(token);
            continue;
        }

        return Err(DriftError::InvalidQuery(format!(
            "Unexpected character: '{}'",
            ch
        )));
    }

    tokens.push(Token::Eof);
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_create() {
        let tokens = tokenize("CREATE (u:User {name: \"Amrit\"})").unwrap();
        assert!(matches!(tokens[0], Token::Create));
        assert!(matches!(tokens[1], Token::LeftParen));
        assert!(matches!(tokens[2], Token::Identifier(_)));
        assert!(matches!(tokens[3], Token::Colon));
    }

    #[test]
    fn test_tokenize_find_with_arrow() {
        let tokens = tokenize("FIND (u)-[:LIKES]->(s)").unwrap();
        assert!(matches!(tokens[0], Token::Find));
        // Tokens: FIND ( u ) - [ : LIKES ] -> ( s ) EOF
        //         0    1 2 3 4 5 6 7     8 9  10 11 12 13
        assert!(matches!(tokens[9], Token::Arrow));
    }

    #[test]
    fn test_tokenize_similar_to() {
        let tokens = tokenize("FIND SIMILAR TO [0.1, 0.5]").unwrap();
        assert!(matches!(tokens[0], Token::Find));
        assert!(matches!(tokens[1], Token::SimilarTo));
    }

    #[test]
    fn test_tokenize_numbers() {
        let tokens = tokenize("42 3.14").unwrap();
        assert!(matches!(tokens[0], Token::IntLiteral(42)));
        assert!(matches!(tokens[1], Token::FloatLiteral(_)));
    }
}
