use reqwest::header::AUTHORIZATION;
use std::convert::TryFrom;
use url::Position;

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    // Send a request to httpbin.org to a url that requires Digest Access Authentication
    let user = "FredJones";
    let password = "P@55w0rd!";
    let test_url = format!("http://httpbin.org/digest-auth/auth/{}/{}", user, password);

    let client = reqwest::Client::new();
    let res = client.get(&test_url).send().await?;

    if let Ok(mut auth) = digest_access::DigestAccess::try_from(res.headers()) {
        let url = res.url().to_owned();
        let body = res.bytes().await;
        let body_slice: Option<&[u8]> = match &body {
            Ok(b) => Some(b),
            Err(_) => None,
        };

        auth.set_username(user);
        auth.set_password(password);
        let authorization = auth
            .generate_authorization("GET", &url[Position::BeforePath..], body_slice, None)
            .unwrap();

        // Repeat the original request with the AUTHORIZATION header
        let body = client
            .get(url)
            .header(AUTHORIZATION, authorization)
            .send()
            .await?
            .text()
            .await?;

        println!("Body:\n{}", body);
    } else {
        println!("Authentication was not required");
    }

    Ok(())
}
