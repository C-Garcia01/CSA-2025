# RAG-VCC (Notre Dame's Summer 2025 Computing Skills Accelerator Program)

### Repair prototype

The fork adds a repository-level repair workflow using Codex CLI or Claude Code. See [REPAIR.md](REPAIR.md) for the local demo, scenario configuration, retrieval format and validation checks. The original generation workflow remains available below.

Vulnerability-detecting machine learning models are becoming more important in cybersecurity because they can help prevent vulnerable software from being published. However, in order to train these models, large amounts of data are necessary. Existing datasets are currently not realistic or diverse enough to address this challenge. RAG-VCC tries to address that issue by using retrieval-augmented generation (RAG) with a large language model to inject vulnerable code into non-vulnerable code snippets. Now with both snippets, we create Vulnerability-Contributing Commits (VCC) that are both realistic and diverse, fit to train vulnerability-detecting models.  

### GitHub-scrapers
Contains scripts to scrape data from GitHub repositories:  
git_file_scraper.py - Retrieves URLs for relevant files from a GitHub repository and stores them in contextURLs.txt.  
git_patch_scraper.py - Retrieves URLs for relevant commit patch files from a GitHub repository and stores them in CommitLinks.txt.  
  
### input-text
Contains text files relevant to the program's input data:  
contextURLs.txt - GitHub context file URLs found by git_file_scraper.py to be used in the program. Includes pieces of vulnerable code to be later used by the model as context.  
inputLinks.txt - GitHub file URLs that will be transformed into vulnerable code.  

### src
Contains the main program python files:  
GitHub_Commit.py - Contains methods involving making commits to GitHub.  
config_loader.py - Loads the information from the config file to be accessed in other parts of the program.  
context_loader.py - Loads the context to be used in RAG and splits it into chunks to prepare for vector search.  
drive_upload.py - Methods to upload LLM’s responses to Google Drive.  
main.py - Main flow of the program that calls various methods to complete the full pipeline.  
process_commits.py - Generates responses from the LLM for each file to be used to generate a VCC.  
qa_chain.py - Contains method to build RAG Question-Answering chain with configuration info such as the LLM to be used.  
vector_store.py - Contains method to make vector embeddings that represent the context chunks for the similarity search.  

### See about section for VCC dataset repo or click link.
https://github.com/mzampino1/CSA-2025-Dataset
