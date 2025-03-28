**THIS IS AN EXPERIMENTAL AND INTERNAL PREVIEW AND NOT INDENTED FOR GENERAL USE YET.**

This app enables auto-merge on PRs that dependabot creates.

## Security

Using this app is more secure than using a `pull_request_target`-triggered GitHub Actions workflow with a Personal Access Token (PAT) because:
* No `pull_request_target`-triggered workflow is needed (contrary to the PAT) so the risk of pwn requests is reduced.
* The GitHub App credentials never enter any GitHub Actions workflow (contrary to the PAT) so the risk for credential leak is very low.
* Even if the GitHub App credentials were to leak somehow they would only give write access to Pull Requests (contrary to the PAT).

## License

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.