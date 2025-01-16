"""Sphinx configuration file for AWS Security Group Mapper documentation."""

import os
import sys
sys.path.insert(0, os.path.abspath('..'))

project = 'AWS Security Group Mapper'
copyright = '2025, AWS Security Group Mapper Contributors'
author = 'AWS Security Group Mapper Contributors'
release = '0.1.0'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx_autodoc_typehints',
    'sphinx.ext.viewcode',
    'sphinx.ext.githubpages',
]

# Mock imports to avoid requiring all dependencies for building docs
autodoc_mock_imports = ["numpy", "matplotlib", "plotly", "networkx", "boto3", "botocore"]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Custom CSS
html_css_files = [
    'custom.css',
]

# AutoDoc settings
autodoc_member_order = 'bysource'
autodoc_typehints = 'description'
add_module_names = False

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_type_aliases = None

# Sidebar settings
html_theme_options = {
    'navigation_depth': 4,
    'collapse_navigation': False,
    'sticky_navigation': True,
    'includehidden': True,
    'titles_only': False,
}