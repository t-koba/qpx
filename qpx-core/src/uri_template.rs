use anyhow::{anyhow, bail, Result};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use regex::Regex;
use std::collections::HashMap;

const SIMPLE_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b':')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b'[')
    .add(b']')
    .add(b'@')
    .add(b'!')
    .add(b'$')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b';')
    .add(b'=')
    .add(b'%');

const RESERVED_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Debug, Clone)]
pub struct UriTemplate {
    source: String,
    parts: Vec<TemplatePart>,
    regex: Regex,
    bindings: Vec<CaptureBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriTemplateValue {
    Scalar(String),
    List(Vec<String>),
    Assoc(Vec<(String, Option<String>)>),
}

#[derive(Debug, Clone)]
enum TemplatePart {
    Literal(String),
    Expr(Expression),
}

#[derive(Debug, Clone)]
struct Expression {
    operator: Operator,
    vars: Vec<VarSpec>,
}

#[derive(Debug, Clone)]
pub struct VarSpec {
    pub name: String,
    pub explode: bool,
    pub prefix: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    Simple,
    Reserved,
    Fragment,
    Label,
    Path,
    PathParam,
    Query,
    QueryContinuation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeMode {
    PercentDecoded,
}

#[derive(Debug, Clone)]
struct CaptureBinding {
    name: String,
    prefix: Option<usize>,
    decode_mode: DecodeMode,
}

impl UriTemplate {
    pub fn parse(template: &str) -> Result<Self> {
        let parts = parse_template_parts(template)?;
        let (regex, bindings) = build_match_regex(&parts)?;
        Ok(Self {
            source: template.to_string(),
            parts,
            regex,
            bindings,
        })
    }

    pub fn source(&self) -> &str {
        self.source.as_str()
    }

    pub fn var_specs(&self) -> impl Iterator<Item = &VarSpec> {
        self.parts.iter().flat_map(|part| match part {
            TemplatePart::Literal(_) => [].iter(),
            TemplatePart::Expr(expr) => expr.vars.iter(),
        })
    }

    pub fn has_recoverable_variable(&self, name: &str) -> bool {
        self.var_specs()
            .any(|spec| spec.name == name && spec.prefix.is_none())
    }

    pub fn expand<F>(&self, mut resolve: F) -> Result<String>
    where
        F: FnMut(&str) -> Option<String>,
    {
        self.expand_values(|name| resolve(name).map(UriTemplateValue::Scalar))
    }

    pub fn expand_values<F>(&self, mut resolve: F) -> Result<String>
    where
        F: FnMut(&str) -> Option<UriTemplateValue>,
    {
        let mut out = String::with_capacity(self.source.len());
        for part in &self.parts {
            match part {
                TemplatePart::Literal(literal) => out.push_str(literal.as_str()),
                TemplatePart::Expr(expr) => {
                    out.push_str(expand_expression(expr, &mut resolve)?.as_str())
                }
            }
        }
        Ok(out)
    }

    pub fn match_scalars(&self, actual: &str) -> Result<HashMap<String, String>> {
        let captures = self
            .regex
            .captures(actual)
            .ok_or_else(|| anyhow!("uri_template mismatch"))?;
        let mut resolved = HashMap::<String, String>::new();
        let mut prefixes = Vec::<(String, usize, String)>::new();
        for (idx, binding) in self.bindings.iter().enumerate() {
            let Some(raw) = captures.get(idx + 1).map(|m| m.as_str()) else {
                continue;
            };
            let decoded = decode_capture(raw, binding.decode_mode)?;
            if let Some(prefix) = binding.prefix {
                prefixes.push((binding.name.clone(), prefix, decoded));
                continue;
            }
            match resolved.get(binding.name.as_str()) {
                Some(existing) if existing != &decoded => {
                    bail!("uri_template variable mismatch for {}", binding.name);
                }
                Some(_) => {}
                None => {
                    resolved.insert(binding.name.clone(), decoded);
                }
            }
        }
        for (name, prefix_len, prefix_value) in prefixes {
            let Some(full) = resolved.get(name.as_str()) else {
                continue;
            };
            if truncate_chars(full.as_str(), prefix_len) != prefix_value {
                bail!("uri_template variable prefix mismatch for {}", name);
            }
        }
        Ok(resolved)
    }
}

fn parse_template_parts(template: &str) -> Result<Vec<TemplatePart>> {
    let mut parts = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel_start) = template[cursor..].find('{') {
        let start = cursor + rel_start;
        if start > cursor {
            parts.push(TemplatePart::Literal(template[cursor..start].to_string()));
        }
        let Some(rel_end) = template[start + 1..].find('}') else {
            bail!("uri_template has unmatched '{{'");
        };
        let end = start + 1 + rel_end;
        let expr = &template[start + 1..end];
        parts.push(TemplatePart::Expr(parse_expression(expr)?));
        cursor = end + 1;
    }
    if cursor < template.len() {
        parts.push(TemplatePart::Literal(template[cursor..].to_string()));
    }
    Ok(parts)
}

fn parse_expression(expr: &str) -> Result<Expression> {
    let expr = expr.trim();
    if expr.is_empty() {
        bail!("uri_template expression must not be empty");
    }
    let (operator, vars_raw) = match expr.as_bytes()[0] {
        b'+' => (Operator::Reserved, &expr[1..]),
        b'#' => (Operator::Fragment, &expr[1..]),
        b'.' => (Operator::Label, &expr[1..]),
        b'/' => (Operator::Path, &expr[1..]),
        b';' => (Operator::PathParam, &expr[1..]),
        b'?' => (Operator::Query, &expr[1..]),
        b'&' => (Operator::QueryContinuation, &expr[1..]),
        _ => (Operator::Simple, expr),
    };
    let mut vars = Vec::new();
    for raw in vars_raw.split(',') {
        vars.push(parse_var_spec(raw)?);
    }
    if vars.is_empty() {
        bail!("uri_template expression must include at least one variable");
    }
    Ok(Expression { operator, vars })
}

fn parse_var_spec(raw: &str) -> Result<VarSpec> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("uri_template variable name must not be empty");
    }
    let (raw, explode) = raw
        .strip_suffix('*')
        .map_or((raw, false), |value| (value, true));
    let (name, prefix) = match raw.split_once(':') {
        Some((name, prefix)) => {
            let prefix = prefix
                .parse::<usize>()
                .map_err(|_| anyhow!("uri_template prefix modifier must be numeric"))?;
            if prefix == 0 {
                bail!("uri_template prefix modifier must be >= 1");
            }
            (name, Some(prefix))
        }
        None => (raw, None),
    };
    if name.is_empty() {
        bail!("uri_template variable name must not be empty");
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
    {
        bail!("uri_template variable name contains unsupported characters");
    }
    Ok(VarSpec {
        name: name.to_string(),
        explode,
        prefix,
    })
}

fn build_match_regex(parts: &[TemplatePart]) -> Result<(Regex, Vec<CaptureBinding>)> {
    let mut pattern = String::from("^");
    let mut bindings = Vec::new();
    for part in parts {
        match part {
            TemplatePart::Literal(literal) => pattern.push_str(regex::escape(literal).as_str()),
            TemplatePart::Expr(expr) => append_expression_regex(&mut pattern, &mut bindings, expr),
        }
    }
    pattern.push('$');
    let regex = Regex::new(pattern.as_str())?;
    Ok((regex, bindings))
}

fn append_expression_regex(
    pattern: &mut String,
    bindings: &mut Vec<CaptureBinding>,
    expr: &Expression,
) {
    match expr.operator {
        Operator::Simple | Operator::Reserved => {
            append_delimited_captures(pattern, bindings, expr, "", ",", "[^,]*");
        }
        Operator::Fragment => {
            append_delimited_captures(pattern, bindings, expr, "#", ",", "[^,]*");
        }
        Operator::Label => {
            append_delimited_captures(pattern, bindings, expr, ".", ".", "[^.]*");
        }
        Operator::Path => {
            append_delimited_captures(pattern, bindings, expr, "/", "/", "[^/]*");
        }
        Operator::PathParam => {
            for var in &expr.vars {
                pattern.push(';');
                pattern.push_str(regex::escape(var.name.as_str()).as_str());
                pattern.push_str("(?:=([^;/?#]*))?");
                bindings.push(CaptureBinding {
                    name: var.name.clone(),
                    prefix: var.prefix,
                    decode_mode: DecodeMode::PercentDecoded,
                });
            }
        }
        Operator::Query | Operator::QueryContinuation => {
            let first_sep = if expr.operator == Operator::Query {
                regex::escape("?")
            } else {
                regex::escape("&")
            };
            for (idx, var) in expr.vars.iter().enumerate() {
                if idx == 0 {
                    pattern.push_str(first_sep.as_str());
                } else {
                    pattern.push_str(regex::escape("&").as_str());
                }
                pattern.push_str(regex::escape(var.name.as_str()).as_str());
                pattern.push('=');
                pattern.push_str("([^&#]*)");
                bindings.push(CaptureBinding {
                    name: var.name.clone(),
                    prefix: var.prefix,
                    decode_mode: DecodeMode::PercentDecoded,
                });
            }
        }
    }
}

fn append_delimited_captures(
    pattern: &mut String,
    bindings: &mut Vec<CaptureBinding>,
    expr: &Expression,
    prefix: &str,
    separator: &str,
    capture_pattern: &str,
) {
    pattern.push_str(regex::escape(prefix).as_str());
    for (idx, var) in expr.vars.iter().enumerate() {
        if idx > 0 {
            pattern.push_str(regex::escape(separator).as_str());
        }
        pattern.push('(');
        pattern.push_str(capture_pattern);
        pattern.push(')');
        bindings.push(CaptureBinding {
            name: var.name.clone(),
            prefix: var.prefix,
            decode_mode: DecodeMode::PercentDecoded,
        });
    }
}

fn expand_expression<F>(expr: &Expression, resolve: &mut F) -> Result<String>
where
    F: FnMut(&str) -> Option<UriTemplateValue>,
{
    let mut items = Vec::new();
    for var in &expr.vars {
        let Some(value) = resolve(var.name.as_str()) else {
            continue;
        };
        expand_varspec(expr, var, value, &mut items)?;
    }

    if items.is_empty() {
        return Ok(String::new());
    }

    let mut out = String::with_capacity(items.iter().map(String::len).sum::<usize>() + 4);
    match expr.operator {
        Operator::Simple | Operator::Reserved => {
            out.push_str(items.join(",").as_str());
        }
        Operator::Fragment => {
            out.push('#');
            out.push_str(items.join(",").as_str());
        }
        Operator::Label => {
            out.push('.');
            out.push_str(items.join(".").as_str());
        }
        Operator::Path => {
            out.push('/');
            out.push_str(items.join("/").as_str());
        }
        Operator::PathParam => {
            for value in items {
                out.push(';');
                out.push_str(value.as_str());
            }
        }
        Operator::Query | Operator::QueryContinuation => {
            out.push(if expr.operator == Operator::Query {
                '?'
            } else {
                '&'
            });
            for (idx, value) in items.iter().enumerate() {
                if idx > 0 {
                    out.push('&');
                }
                out.push_str(value.as_str());
            }
        }
    }
    Ok(out)
}

fn expand_varspec(
    expr: &Expression,
    var: &VarSpec,
    value: UriTemplateValue,
    items: &mut Vec<String>,
) -> Result<()> {
    match value {
        UriTemplateValue::Scalar(raw) => {
            let raw = if let Some(prefix) = var.prefix {
                truncate_chars(raw.as_str(), prefix)
            } else {
                raw
            };
            items.push(expand_scalar_item(
                expr.operator,
                var.name.as_str(),
                raw.as_str(),
            ));
        }
        UriTemplateValue::List(values) => {
            if var.prefix.is_some() {
                bail!(
                    "uri_template prefix modifier is not allowed on list variable {}",
                    var.name
                );
            }
            if values.is_empty() {
                return Ok(());
            }
            if var.explode {
                if expr.operator.expands_named_members() {
                    for value in values {
                        items.push(expand_named_member(
                            expr.operator,
                            var.name.as_str(),
                            value.as_str(),
                        ));
                    }
                } else {
                    for value in values {
                        items.push(encode_value(
                            value.as_str(),
                            expr.operator.allows_reserved(),
                        ));
                    }
                }
            } else {
                items.push(expand_non_exploded_composite(
                    expr.operator,
                    var.name.as_str(),
                    values
                        .into_iter()
                        .map(|value| encode_value(value.as_str(), expr.operator.allows_reserved()))
                        .collect(),
                ));
            }
        }
        UriTemplateValue::Assoc(entries) => {
            if var.prefix.is_some() {
                bail!(
                    "uri_template prefix modifier is not allowed on assoc variable {}",
                    var.name
                );
            }
            let defined = entries
                .into_iter()
                .filter_map(|(name, value)| value.map(|value| (name, value)))
                .collect::<Vec<_>>();
            if defined.is_empty() {
                return Ok(());
            }
            if var.explode {
                for (name, value) in defined {
                    let encoded_name = encode_value(name.as_str(), expr.operator.allows_reserved());
                    let encoded_value =
                        encode_value(value.as_str(), expr.operator.allows_reserved());
                    if encoded_value.is_empty() && !expr.operator.expands_form_query() {
                        items.push(encoded_name);
                    } else {
                        items.push(format!("{encoded_name}={encoded_value}"));
                    }
                }
            } else {
                let mut flattened = Vec::with_capacity(defined.len() * 2);
                for (name, value) in defined {
                    flattened.push(encode_value(name.as_str(), expr.operator.allows_reserved()));
                    flattened.push(encode_value(
                        value.as_str(),
                        expr.operator.allows_reserved(),
                    ));
                }
                items.push(expand_non_exploded_composite(
                    expr.operator,
                    var.name.as_str(),
                    flattened,
                ));
            }
        }
    }
    Ok(())
}

fn expand_scalar_item(operator: Operator, name: &str, raw: &str) -> String {
    let encoded = encode_value(raw, operator.allows_reserved());
    if operator.expands_named_members() {
        if encoded.is_empty() && operator == Operator::PathParam {
            name.to_string()
        } else {
            format!("{name}={encoded}")
        }
    } else {
        encoded
    }
}

fn expand_named_member(operator: Operator, name: &str, raw: &str) -> String {
    let encoded = encode_value(raw, operator.allows_reserved());
    if encoded.is_empty() && operator == Operator::PathParam {
        name.to_string()
    } else {
        format!("{name}={encoded}")
    }
}

fn expand_non_exploded_composite(
    operator: Operator,
    name: &str,
    encoded_members: Vec<String>,
) -> String {
    let joined = encoded_members.join(",");
    if operator.expands_named_members() {
        if joined.is_empty() && operator == Operator::PathParam {
            name.to_string()
        } else {
            format!("{name}={joined}")
        }
    } else {
        joined
    }
}

fn decode_capture(raw: &str, _mode: DecodeMode) -> Result<String> {
    Ok(percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| anyhow!("uri_template capture is not valid UTF-8"))?
        .into_owned())
}

fn encode_value(value: &str, allow_reserved: bool) -> String {
    let set = if allow_reserved {
        RESERVED_ENCODE_SET
    } else {
        SIMPLE_ENCODE_SET
    };
    utf8_percent_encode(value, set).to_string()
}

fn truncate_chars(value: &str, prefix: usize) -> String {
    value.chars().take(prefix).collect::<String>()
}

impl Operator {
    fn allows_reserved(self) -> bool {
        matches!(self, Operator::Reserved | Operator::Fragment)
    }

    fn expands_named_members(self) -> bool {
        matches!(
            self,
            Operator::PathParam | Operator::Query | Operator::QueryContinuation
        )
    }

    fn expands_form_query(self) -> bool {
        matches!(self, Operator::Query | Operator::QueryContinuation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_path_and_query_operators() {
        let template =
            UriTemplate::parse("/masque{/target_host,target_port}{?target_host,target_port}")
                .expect("template");
        let expanded = template
            .expand(|name| match name {
                "target_host" => Some("2001:db8::42".to_string()),
                "target_port" => Some("8443".to_string()),
                _ => None,
            })
            .expect("expand");
        assert_eq!(
            expanded,
            "/masque/2001%3Adb8%3A%3A42/8443?target_host=2001%3Adb8%3A%3A42&target_port=8443"
        );
    }

    #[test]
    fn matches_recoverable_and_prefixed_variables() {
        let template = UriTemplate::parse("/udp/{target_host}/{target_host:3}/{target_port}")
            .expect("template");
        let matched = template
            .match_scalars("/udp/example.com/exa/443")
            .expect("match");
        assert_eq!(
            matched.get("target_host").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(matched.get("target_port").map(String::as_str), Some("443"));
    }

    #[test]
    fn rejects_prefix_mismatch() {
        let template = UriTemplate::parse("/udp/{target_host}/{target_host:3}/{target_port}")
            .expect("template");
        assert!(template.match_scalars("/udp/example.com/foo/443").is_err());
    }

    #[test]
    fn expands_rfc6570_composite_examples() {
        let template = UriTemplate::parse("{/list*}{?keys*}{;empty}").expect("template");
        let expanded = template
            .expand_values(|name| match name {
                "list" => Some(UriTemplateValue::List(vec![
                    "red".to_string(),
                    "green".to_string(),
                    "blue".to_string(),
                ])),
                "keys" => Some(UriTemplateValue::Assoc(vec![
                    ("semi".to_string(), Some(";".to_string())),
                    ("dot".to_string(), Some(".".to_string())),
                    ("comma".to_string(), Some(",".to_string())),
                ])),
                "empty" => Some(UriTemplateValue::Scalar(String::new())),
                _ => None,
            })
            .expect("expand");
        assert_eq!(expanded, "/red/green/blue?semi=%3B&dot=.&comma=%2C;empty");
    }

    #[test]
    fn expands_non_exploded_assoc_and_undefined_values() {
        let template = UriTemplate::parse("{?keys,count,undef}").expect("template");
        let expanded = template
            .expand_values(|name| match name {
                "keys" => Some(UriTemplateValue::Assoc(vec![
                    ("semi".to_string(), Some(";".to_string())),
                    ("dot".to_string(), Some(".".to_string())),
                    ("skip".to_string(), None),
                ])),
                "count" => Some(UriTemplateValue::List(vec![
                    "one".to_string(),
                    "two".to_string(),
                    "three".to_string(),
                ])),
                "undef" => None,
                _ => None,
            })
            .expect("expand");
        assert_eq!(expanded, "?keys=semi,%3B,dot,.&count=one,two,three");
    }
}
