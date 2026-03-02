# Organization to Team Members

Finds an organization's team pages and extracts team members using OpenAI.

## Input / Output

- **Input**: `Organization`
- **Output**: `Person`

## API Keys Required

- **OpenAI API key** (`OPENAI_API_KEY`) — get one at https://platform.openai.com/api-keys

Configure via Settings > API Keys in the OGI UI (`openai` service).

## Transform Settings

- `openai_model` — model used for extraction
- `max_members` — maximum members to return (1-500, default 500)

## Notes

- The transform discovers likely team/about pages, scrapes page text, and asks OpenAI to extract structured member data.
- Returned members are linked to the organization with a `team_member` edge.
