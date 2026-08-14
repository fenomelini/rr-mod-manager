use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    String(String),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            Self::Object(_) => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Self::Object(value) => Some(value),
            Self::String(_) => None,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VdfError {
    #[error("unexpected end of VDF input")]
    UnexpectedEnd,
    #[error("unterminated quoted string at byte {0}")]
    UnterminatedString(usize),
    #[error("unexpected character '{character}' at byte {offset}")]
    UnexpectedCharacter { character: char, offset: usize },
    #[error("expected {expected} at token {token}")]
    UnexpectedToken {
        expected: &'static str,
        token: usize,
    },
    #[error("duplicate VDF key '{0}'")]
    DuplicateKey(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Text(String),
    Open,
    Close,
}

pub fn parse(input: &str) -> Result<BTreeMap<String, Value>, VdfError> {
    let tokens = tokenize(input)?;
    let mut cursor = 0;
    let result = parse_object(&tokens, &mut cursor, false)?;
    if cursor != tokens.len() {
        return Err(VdfError::UnexpectedToken {
            expected: "end of input",
            token: cursor,
        });
    }
    Ok(result)
}

fn parse_object(
    tokens: &[Token],
    cursor: &mut usize,
    nested: bool,
) -> Result<BTreeMap<String, Value>, VdfError> {
    let mut result = BTreeMap::new();
    loop {
        match tokens.get(*cursor) {
            Some(Token::Close) if nested => {
                *cursor += 1;
                return Ok(result);
            }
            None if nested => return Err(VdfError::UnexpectedEnd),
            None => return Ok(result),
            Some(Token::Text(_)) => {}
            Some(_) => {
                return Err(VdfError::UnexpectedToken {
                    expected: "a quoted key",
                    token: *cursor,
                });
            }
        }

        let Token::Text(key) = &tokens[*cursor] else {
            unreachable!();
        };
        let key = key.clone();
        *cursor += 1;

        let value = match tokens.get(*cursor) {
            Some(Token::Text(value)) => {
                *cursor += 1;
                Value::String(value.clone())
            }
            Some(Token::Open) => {
                *cursor += 1;
                Value::Object(parse_object(tokens, cursor, true)?)
            }
            Some(_) => {
                return Err(VdfError::UnexpectedToken {
                    expected: "a quoted value or opening brace",
                    token: *cursor,
                });
            }
            None => return Err(VdfError::UnexpectedEnd),
        };

        if result.insert(key.clone(), value).is_some() {
            return Err(VdfError::DuplicateKey(key));
        }
    }
}

fn tokenize(input: &str) -> Result<Vec<Token>, VdfError> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some((offset, character)) = chars.next() {
        match character {
            value if value.is_whitespace() => {}
            '/' if chars.peek().is_some_and(|(_, next)| *next == '/') => {
                chars.next();
                for (_, next) in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
            }
            '{' => tokens.push(Token::Open),
            '}' => tokens.push(Token::Close),
            '"' => {
                let mut value = String::new();
                let mut closed = false;
                while let Some((_, next)) = chars.next() {
                    match next {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => match chars.next() {
                            Some((_, '"')) => value.push('"'),
                            Some((_, '\\')) => value.push('\\'),
                            Some((_, escaped)) => {
                                value.push('\\');
                                value.push(escaped);
                            }
                            None => return Err(VdfError::UnterminatedString(offset)),
                        },
                        value_character => value.push(value_character),
                    }
                }
                if !closed {
                    return Err(VdfError::UnterminatedString(offset));
                }
                tokens.push(Token::Text(value));
            }
            _ => return Err(VdfError::UnexpectedCharacter { character, offset }),
        }
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_objects_comments_and_escaped_paths() {
        let parsed = parse(
            r#"
            // Steam library data
            "libraryfolders"
            {
                "0" { "path" "C:\\Steam" }
            }
            "#,
        )
        .unwrap();

        let path = parsed["libraryfolders"].as_object().unwrap()["0"]
            .as_object()
            .unwrap()["path"]
            .as_str();
        assert_eq!(path, Some("C:\\Steam"));
    }

    #[test]
    fn rejects_duplicate_keys() {
        let error = parse(r#""root" { "key" "a" "key" "b" }"#).unwrap_err();
        assert_eq!(error, VdfError::DuplicateKey("key".to_owned()));
    }
}
