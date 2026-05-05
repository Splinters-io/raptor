"""GPU-Fuzz: LLM-guided mutation for AFL++ fuzzing campaigns.

Uses local LLMs (via Ollama) to generate semantically intelligent
mutations based on decompiled parser code and coverage feedback.
Random bitflips find shallow bugs. LLM-guided mutations find deep ones.
"""
