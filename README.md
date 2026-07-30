# VulnForge: Building Enhanced OSS Vulnerability Datasets via Uncertainty-based Agentic Patch Analysis

Welcome to VulnForge repository! Our framework consists of three key modules that enhance the quality of open-source software vulnerability datasets: Patch Decomposition, Inter-Procedural Context Extraction, and Patch Untangling using Context .

# Repository Structure

```text
VulnForge/
|-- code/
|   -- common/
|   -- patch_decomposition/
|   -- inter_procedural_context_extraction/
|   -- patch_untangling/
|   -- experiments/
|-- data/
|-- results/
```

- `code/`: Source code for the full VulnForge pipeline.
  - `common/`: Shared utilities for dataset normalization, I/O, prompting, modeling, and evaluation metrics.
  - `patch_decomposition/`: Splits vulnerability-fixing commits into candidate sub-patches and verifies commit-level metadata.
  - `inter_procedural_context_extraction/`: Builds inter-procedural context for each patch using static analysis and graph-based traversal.
  - `patch_untangling/`: Runs the agentic patch untangling stage to classify relevant and irrelevant sub-patches.
  - `experiments/`: Scripts for ablation studies, benchmarking, finetuning data preparation, and evaluation.
- `data/`: Dataset notes and links for the original vulnerability datasets used by VulnForge.
- `results/`: Generated outputs and experiment artifacts.
  - `untangling_results/`: Outputs from the patch untangling stage.
  - `benchmark_results/`: Benchmark comparisons across datasets and model settings.
  - `finetuning_results/`: Intermediate files and evaluation outputs for finetuning experiments.

# Environment

### 1. Programming Language  

Python 3.10 or higher

### 2. [Tree-sitter](https://github.com/tree-sitter/tree-sitter) 

```bash
pip install tree-sitter tree-sitter-c tree-sitter-cpp
```

- `tree_sitter` requires compiling a library for the target language (in this case, C/C++)

- With Tree-sitter, you can:
    -  parse source files into syntax trees, 
    -  query functions, statements, and code structures, 
    -  extract syntax-aware patch information.

### 3. [Cflow](https://www.gnu.org/software/cflow)

```bash
sudo apt install cflow
```

`cflow` is a static analysis tool for C programs that generates function call hierarchies. 
 It helps identify:

-  which function calls which, 
-  caller-callee relationships across files, 
-  higher-level context paths related to a patch.

# Quick Start

1. Install the required Python packages and external tools listed in the Environment section.
2. Download the original datasets referenced in [data/datasets.md](data/datasets.md) and place them in your local workspace.
3. Open the three pipeline entry files and replace each `xxx` placeholder with your local dataset paths, repository paths, output paths, model paths, and tokens as needed:
   - `code/patch_decomposition/main.py`
   - `code/inter_procedural_context_extraction/main.py`
   - `code/patch_untangling/main.py`
4. Run the pipeline in order from the repository root:

```bash
python code/patch_decomposition/main.py
python code/inter_procedural_context_extraction/main.py
python code/patch_untangling/main.py
```

5. Optional experiment scripts are available in `code/experiments/` for ablation, benchmarking, and downstream evaluation.


# Datasets  

Original datasets: 

| Datasets   | CWE Types | Samples | Labeling Method        | Language            |
| ---------- | --------- | ------- | ---------------------- | ------------------- |
| BigVul     | 91        | 3,754   | Commit Code Diff       | C/C++               |
| D2A        | ---       | 9,652   | Static Analysis        | C/C++               |
| DiverseVul | 150       | 7,514   | Commit Code Diff       | C/C++               |
| ReposVul   | 236       | 6,134   | LLMs + static Analysis | C/C++、Python、Java |



 Patch untangling results of all 1,714 samples:

<table>
  <thead>
    <tr>
      <th rowspan="2">Datasets</th>
      <th rowspan="2">CVE Samples</th>
      <th colspan="3">Sub-patches</th>
    </tr>
    <tr>
      <th>Relevant</th>
      <th>Irrelevant</th>
      <th>Total</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>BigVul</td>
      <td>358</td>
      <td>672</td>
      <td>1,032</td>
      <td>1,704</td>
    </tr>
    <tr>
      <td>D2A</td>
      <td>500</td>
      <td>2,458</td>
      <td>2,393</td>
      <td>4,851</td>
    </tr>
    <tr>
      <td>DiverseVul</td>
      <td>478</td>
      <td>753</td>
      <td>1,521</td>
      <td>2,274</td>
    </tr>
    <tr>
      <td>ReposVul</td>
      <td>378</td>
      <td>1,023</td>
      <td>774</td>
      <td>1,797</td>
    </tr>
    <tr>
      <td>Overall</td>
      <td>1,714</td>
      <td>4,906</td>
      <td>5,720</td>
      <td>10,626</td>
    </tr>
  </tbody>
</table>

