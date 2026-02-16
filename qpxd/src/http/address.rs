use hyper::Uri;

pub fn parse_authority_host_port(input: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = if input.contains(':') || input.starts_with('[') {
        input.to_string()
    } else {
        format!("{}:{}", input, default_port)
    };

    let uri = Uri::builder()
        .scheme("http")
        .authority(authority.as_str())
        .path_and_query("/")
        .build()
        .ok()?;
    let auth = uri.authority()?;
    let host = auth.host().to_string();
    let port = auth.port_u16().unwrap_or(default_port);
    Some((host, port))
}

pub fn format_authority_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}
