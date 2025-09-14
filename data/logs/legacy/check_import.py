import sys

print("python", sys.version.replace("\n", " "))
try:
    import llama_cpp
    import llama_cpp.server

    print("llama_cpp", getattr(llama_cpp, "__version__", "?"))
except Exception as e:
    print("IMPORT_ERROR", e)
    raise
