import os
import sys
sys.path.insert(0, os.path.abspath("../src"))

project = "DataShield"
copyright = "2026, Carlos Rocha"
author = "Carlos Rocha"
release = "0.1.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]
templates_path = ["_templates"]
exclude_patterns = ["_build"]
html_theme = "furo"
