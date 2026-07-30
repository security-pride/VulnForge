import sys
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from common.modeling import generate_analysis, load_generation_bundle


class HuggingFacePatchAgent:
    def __init__(self, model_path, temperature=0.0, max_new_tokens=256):
        self.model_path = model_path
        self.temperature = temperature
        self.max_new_tokens = max_new_tokens
        self.bundle = None

    def load(self):
        if self.bundle is None:
            self.bundle = load_generation_bundle(self.model_path)
        return self.bundle

    def analyze(self, prompt):
        return generate_analysis(self.load(), prompt, temperature=self.temperature, max_new_tokens=self.max_new_tokens)
