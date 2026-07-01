"""
Runs the adversarial corpus through both scanners and prints a detection-rate
report - the concrete evidence you'd screenshot into a portfolio README.

Usage: python -m tests.adversarial.run_benchmark   (run from repo root)
"""
import json
import os
from gateway.security import injection_scanner, pii_scanner

CORPUS_PATH = os.path.join(os.path.dirname(__file__), "corpus.json")


def evaluate_injection(corpus):
    malicious = corpus["prompt_injection"]["malicious"]
    benign = corpus["prompt_injection"]["benign"]

    true_positives = sum(
        1 for text in malicious
        if any(f.confidence >= 0.6 for f in injection_scanner.scan_text(text))
    )
    false_positives = sum(
        1 for text in benign
        if any(f.confidence >= 0.6 for f in injection_scanner.scan_text(text))
    )
    return {
        "detection_rate": true_positives / len(malicious),
        "true_positives": true_positives,
        "total_malicious": len(malicious),
        "false_positive_rate": false_positives / len(benign),
        "false_positives": false_positives,
        "total_benign": len(benign),
    }


def evaluate_pii(corpus):
    positive = corpus["pii_secrets"]["positive"]
    negative = corpus["pii_secrets"]["negative"]

    true_positives = sum(1 for text in positive if pii_scanner.scan_text(text))
    false_positives = sum(1 for text in negative if pii_scanner.scan_text(text))
    return {
        "detection_rate": true_positives / len(positive),
        "true_positives": true_positives,
        "total_positive": len(positive),
        "false_positive_rate": false_positives / len(negative),
        "false_positives": false_positives,
        "total_negative": len(negative),
    }


def main():
    with open(CORPUS_PATH, encoding="utf-8") as f:
        corpus = json.load(f)

    injection_results = evaluate_injection(corpus)
    pii_results = evaluate_pii(corpus)

    print("=" * 60)
    print("ADVERSARIAL BENCHMARK RESULTS")
    print("=" * 60)
    print("\n[Prompt Injection Scanner]")
    print(f"  Detection rate:      {injection_results['detection_rate']:.0%} "
          f"({injection_results['true_positives']}/{injection_results['total_malicious']})")
    print(f"  False positive rate: {injection_results['false_positive_rate']:.0%} "
          f"({injection_results['false_positives']}/{injection_results['total_benign']})")

    print("\n[PII / Secrets Scanner]")
    print(f"  Detection rate:      {pii_results['detection_rate']:.0%} "
          f"({pii_results['true_positives']}/{pii_results['total_positive']})")
    print(f"  False positive rate: {pii_results['false_positive_rate']:.0%} "
          f"({pii_results['false_positives']}/{pii_results['total_negative']})")
    print("=" * 60)


if __name__ == "__main__":
    main()
