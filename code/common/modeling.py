import math
import re


def extract_decision_and_rationale(text):
    normalized = text.strip()
    first_line = normalized.splitlines()[0].strip().lower() if normalized else ""
    match = re.search(r"\b(yes|no)\b", first_line)
    if match is None:
        match = re.search(r"\b(yes|no)\b", normalized.lower())
    decision = match.group(1) if match else None
    rationale = normalized
    if decision and "\n" in normalized:
        rationale = "\n".join(normalized.splitlines()[1:]).strip() or normalized
    return decision, rationale


def load_generation_bundle(model_path):
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(model_path, trust_remote_code=True)
    return {"tokenizer": tokenizer, "model": model}


def candidate_token_ids(tokenizer):
    yes_tokens = tokenizer.encode(" yes", add_special_tokens=False) or tokenizer.encode("yes", add_special_tokens=False)
    no_tokens = tokenizer.encode(" no", add_special_tokens=False) or tokenizer.encode("no", add_special_tokens=False)
    return yes_tokens[-1], no_tokens[-1]


def binary_entropy(score_yes, score_no):
    max_score = max(score_yes, score_no)
    exp_yes = math.exp(score_yes - max_score)
    exp_no = math.exp(score_no - max_score)
    total = exp_yes + exp_no
    probability_yes = exp_yes / total
    probability_no = exp_no / total
    entropy = 0.0
    for probability in (probability_yes, probability_no):
        if probability > 0:
            entropy -= probability * math.log(probability)
    return entropy


def normalized_perplexity(perplexity):
    if perplexity <= 1:
        return 0.0
    return 1 - 1 / perplexity


def compute_rationale_perplexity(bundle, rationale):
    if not rationale.strip():
        return 1.0, 0.0
    import torch

    tokenizer = bundle["tokenizer"]
    model = bundle["model"]
    inputs = tokenizer(rationale, return_tensors="pt")
    with torch.no_grad():
        output = model(**inputs, labels=inputs["input_ids"])
    perplexity = float(torch.exp(output.loss).item())
    return perplexity, normalized_perplexity(perplexity)


def generate_analysis(bundle, prompt, temperature=0.0, max_new_tokens=256):
    import torch

    tokenizer = bundle["tokenizer"]
    model = bundle["model"]
    inputs = tokenizer(prompt, return_tensors="pt")
    generation = model.generate(
        **inputs,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
        do_sample=temperature > 0,
        return_dict_in_generate=True,
        output_scores=True,
        pad_token_id=tokenizer.eos_token_id,
    )
    generated_ids = generation.sequences[0][inputs["input_ids"].shape[1] :]
    text = tokenizer.decode(generated_ids, skip_special_tokens=True).strip()
    decision, rationale = extract_decision_and_rationale(text)
    yes_token_id, no_token_id = candidate_token_ids(tokenizer)
    entropy = 0.0
    if generation.scores:
        first_scores = generation.scores[0][0]
        entropy = binary_entropy(float(first_scores[yes_token_id]), float(first_scores[no_token_id]))
    perplexity, normalized = compute_rationale_perplexity(bundle, rationale)
    return {
        "raw_output": text,
        "decision": decision,
        "rationale": rationale,
        "predictive_entropy": entropy,
        "rationale_perplexity": perplexity,
        "normalized_rationale_perplexity": normalized,
    }
