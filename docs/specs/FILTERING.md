# FRONTEND APP Filtering 

## GOAL 

Stremlit app includes filtering such that:
- There is a filtering section directly above the "Views" toggle in the left nav 
- User selects a CVSS score to filter on 
- User can also select to filter by a selection of SEVERITY scores, for example: 
  - CRITICAL 
  - CRITICAL, HIGH 
- The default filtering is 8.0 


## FILTERING BY CVSS 

- This will be a slider and the ability to input text
- the default value is 8.0 
- The filter will include CVEs whenever EITHER/ANY/OR of the columns have a score greater than or equal to the input value: 
  - base-score
  - rel-base-score 
- If filtering by CVSS is selected, it's the only filter applied
- Do not assume the minimum base-score or rel-base-score is 0
- assign the minimum CVSS filter based on the minimum value of base-score or rel-base-score across ALL data files available to you 

## FILTERING BY SEVERITY 
- when filtering by severity, the user selects from a drop down 
- user can select multiple severities to filter on 
- this will be an OR operator, selecting HIGH & CRITICAL will return any CVE meeting either criteria


## Actions 

1. Get required context 
2. discuss with me on how you plan to implement filtering 
3. build 
4. test 
5. adjust the raw data script at a later date


## UPDATE rh-summarize.sh 

- rh-summarize.sh filters CVEs greater than 8.0 on base-score OR rel-base-score columns
- remove filtering from rh-summarize.sh
- rh-summarize.sh should return all CVEs 
- rh-summarize.sh should not filter at all 
