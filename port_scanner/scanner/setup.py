from setuptools import Extension, setup
from Cython.Build import cythonize
import os

# Get the current directory
current_dir = os.path.dirname(os.path.abspath(__file__))

extensions = [
    Extension(
        "scanner", # Simpler name for local build
        [os.path.join(current_dir, "scanner.pyx")],
        # Example: include_dirs=[numpy.get_include()] if using numpy
        # Example: libraries=["m"] for math library if needed from C
        # Example: extra_compile_args=["-O3"],
        # Example: extra_link_args=[]
    )
]

setup(
    ext_modules=cythonize(
        extensions,
        compiler_directives={'language_level': "3"}, # Or "3str" for Python 3 string behavior
        # annotate=True # Generates an HTML file for Cython code analysis, useful for debugging
    )
)
