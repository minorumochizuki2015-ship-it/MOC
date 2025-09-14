from llama_cpp import Llama

print("LOADING")
Llama(
    model_path=r"""C:\models\qwen2-7b-instruct-q4_k_m.gguf""",
    n_gpu_layers=0,
    verbose=False,
)
print("OK_LOADED")
