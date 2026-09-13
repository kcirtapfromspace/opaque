//! Read-only source diagnostic. This does not plan, approve or execute a task.
use opaque_core::inference::github::GithubCiSource;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: capture_public_github_ci OWNER/REPO WORKFLOW_ID BRANCH".into());
    }
    let source = GithubCiSource {
        repository: args[0].clone(),
        workflow_id: args[1].parse()?,
        branch: args[2].clone(),
    };
    let snapshot = opaque_bounded_work::inference::capture_public_github_ci(&source).await?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}
