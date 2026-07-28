\---

name: investigate-endpoint

description: Full endpoint investigation combining Hayabusa MCP analysis and detection coverage

\---



\# Endpoint Investigation Workflow



\## Input



Arguments:



$ARGUMENTS



Interpret arguments as:



\- First argument: endpoint hostname

\- Second argument: EVTX evidence path



Example:



/investigate-endpoint WIN-CLIENT01 C:\\logs\\WIN-CLIENT01



\## Step 0 - Validate Evidence



Before running any Hayabusa tools:



1\. Extract the EVTX path from the arguments.

2\. Confirm the path exists.

3\. Confirm it contains .evtx files.

4\. If no EVTX files exist, ask the user for a valid evidence path.



Do not run analysis without evidence.





\## Step 1 - Initial Analysis



Use Hayabusa MCP tools to analyse available EVTX data.



Run:



\- scan\_evtx

\- hayabusa\_log\_metrics

\- hayabusa\_computer\_metrics





\## Step 2 - Investigate Findings



For suspicious activity:



Use:



\- hayabusa\_search

\- hayabusa\_json\_timeline

\- hayabusa\_pivot\_keywords\_list





Look for:



\- suspicious processes

\- command lines

\- users

\- authentication activity

\- persistence indicators





\## Step 3 - Detection Coverage



For identified ATT\&CK techniques:



Use:



\- analyze\_coverage

\- hayabusa://attack/techniques/{technique\_id}

\- suggest\_rule





Determine:



\- covered techniques

\- missing detection coverage

\- relevant Sigma rules





\## Step 4 - Generate Investigation Note



Create a Markdown report:



\# Endpoint Investigation



\## Endpoint



\## Timeline



\## Findings



\## ATT\&CK Techniques



\## Detection Coverage



| Technique | Status | Rule |

|---|---|---|



\## Recommendations

