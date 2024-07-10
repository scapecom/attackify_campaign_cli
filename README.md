# ATTACKIFY Threat Actor Campaign CLI Tool

## Introduction

ATTACKIFY Threat Actor Campaign CLI is a powerful tool designed to interface with the ATTACKIFY API and MITRE ATT&CK framework. This command-line interface allows security professionals and researchers to explore threat actor techniques, map them to ATTACKIFY simulation modules, and automagically create targeted campaign emulations based on real-world threat actor behaviors directly from Mitre ATT&CK.

Blog post about it: <a href="https://www.attackify.com/blog/bridging_mitre_attck_attackify/" target="_blogpost">Bridging Mitre ATT&CK and ATTACKIFY</a>

## Features

- List recent MITRE ATT&CK threat actor groups
- Search for MITRE ATT&CK techniques used by specific threat actor groups
- View available ATTACKIFY environments
- Explore ATTACKIFY simulation modules
- Map MITRE ATT&CK techniques to ATTACKIFY modules
- Create new campaign emulations based on MITRE ATT&CK group techniques

## Installation

1. Clone this repository:

```bash
git clone https://github.com/scapecom/attackify_campaign_cli.git
cd attackify_campaign_cli
```

2. Create a virtual environment (optional but recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use venv\Scripts\activate
```

3. Install the required packages:

```bash
pip install -r requirements.txt
```

## Usage

Run the CLI with your ATTACKIFY API token (beta version to use Bearer Token for now), also to automagically run ATTACKIFY Campaigns from Mitre ATT&CK threat groups, you will need a PROFESSIONAL account with ATTACKIFY. You can still run the tool with a FREE tier to extract mappings between ATT&CK TTPs and ATTACKIFY modules:

```bash
python attackify_cli.py --token YOUR_API_TOKEN_HERE
```

Follow the on-screen menu to navigate through different options and functionalities.

## Features in Detail

1. **Search for MITRE ATT&CK techniques**: Enter a threat actor group name to see all associated techniques.
2. **List recent threat groups**: View the most recently added threat actor groups in the MITRE ATT&CK database.
3. **View environments**: See all available ATTACKIFY environments for your organization.
4. **View simulation modules**: Explore available ATTACKIFY simulation modules and their details.
5. **Map techniques to modules**: Enter a threat actor group to see its techniques and matching ATTACKIFY modules.
6. **Create new campaign**: Design a new campaign based on a specific threat actor group's techniques.


## License

MIT License

Copyright (c) 2024 SCAPECOM/ATTACKIFY

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Disclaimer

This tool is for educational and research purposes only. Always ensure you have proper authorization before performing any security testing or simulations via ATTACKIFY.