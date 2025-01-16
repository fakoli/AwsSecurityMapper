Installation Guide
================

System Requirements
-----------------

- Python 3.8 or higher
- Graphviz (for network visualization)

Installing from Source
--------------------

1. Clone the repository:

   .. code-block:: bash

      git clone <repository-url>
      cd aws-sg-mapper

2. Install dependencies:

   .. code-block:: bash

      pip install -r requirements.txt

3. Configure AWS credentials:

   .. code-block:: bash

      # Option 1: AWS CLI (Recommended)
      aws configure

      # Option 2: Environment variables
      export AWS_ACCESS_KEY_ID="your_access_key"
      export AWS_SECRET_ACCESS_KEY="your_secret_key"
      export AWS_DEFAULT_REGION="us-east-1"

Development Installation
----------------------

For development, you'll need additional packages:

.. code-block:: bash

   pip install -r requirements-dev.txt

This will install additional dependencies like:
- sphinx (for documentation)
- pytest (for testing)
- black (for code formatting)
- pylint (for code analysis)