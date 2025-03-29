#[derive(graphql_client::GraphQLQuery)]
#[graphql(
    schema_path = "github_schema.graphql",
    query_path = "add_comment.graphql",
    variables_derives = "Clone, Debug",
    response_derives = "Clone, Debug"
)]
pub struct IssuesQuery;


fn main() {
    println!("Hello, world!");
}
