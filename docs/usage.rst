Using AWS Security Group Mapper
=============================

Basic Usage
----------

The AWS Security Group Mapper provides several ways to analyze and visualize your AWS security group relationships:

Basic Mapping
~~~~~~~~~~~~

To generate a complete security group map:

.. code-block:: bash

   python aws_sg_mapper.py --profiles default --regions us-east-1

This will create a visualization of all security groups in the specified region.

Filtering Security Groups
~~~~~~~~~~~~~~~~~~~~~~~~

To analyze specific security groups:

.. code-block:: bash

   python aws_sg_mapper.py --profiles default --security-group-ids sg-123456 sg-789012

Multi-Region Analysis
~~~~~~~~~~~~~~~~~~~

To analyze security groups across multiple regions:

.. code-block:: bash

   python aws_sg_mapper.py --profiles default --regions us-east-1 us-west-2

Visualization Options
-------------------

The tool supports two visualization engines:

1. Plotly (Interactive)
   - Zoom and pan capabilities
   - Hover information
   - Draggable nodes

2. Matplotlib (Static)
   - High-resolution exports
   - Perfect for documentation

Configure your preferred engine in ``config.yaml``:

.. code-block:: yaml

   visualization:
     default_engine: "plotly"  # or "matplotlib"

Debug Mode
---------

For troubleshooting, enable debug mode:

.. code-block:: bash

   python aws_sg_mapper.py --profiles default --debug

This provides detailed logging information about the mapping process.

Output Files
-----------

All output files are generated in the ``build/maps/`` directory:

- ``sg_map.html`` - Interactive Plotly visualization
- ``sg_map.png`` - Static Matplotlib visualization
- Individual security group maps (when using ``--output-per-sg``)

Configuration
------------

The tool's behavior can be customized through ``config.yaml``. Key configuration sections include:

- Cache settings
- AWS settings
- Visualization preferences
- CIDR block naming

For detailed configuration options, see the :doc:`configuration` section.

Common Issues
------------

AWS Connectivity
~~~~~~~~~~~~~~

1. **Credential Issues**
   - Run ``aws configure list`` to verify profile
   - Check environment variables
   - Verify AWS CLI installation

2. **Access Denied**
   - Verify IAM permissions
   - Check security token expiration
   - Confirm correct region setting

Visualization
~~~~~~~~~~~~

1. **Performance Issues**
   - Adjust node size in config for large graphs
   - Use filtering options
   - Enable caching

For more troubleshooting tips, see the :doc:`troubleshooting` section.