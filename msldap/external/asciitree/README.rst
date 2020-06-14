ASCII Trees
===========

.. code:: console

  asciitree
   +-- sometimes
   |   +-- you
   +-- just
   |   +-- want
   |       +-- to
   |       +-- draw
   +-- trees
   +-- in
       +-- your
           +-- terminal


.. code:: python

  from asciitree import LeftAligned
  from collections import OrderedDict as OD

  tree = {
      'asciitree': OD([
          ('sometimes',
              {'you': {}}),
          ('just',
              {'want': OD([
                  ('to', {}),
                  ('draw', {}),
              ])}),
          ('trees', {}),
          ('in', {
              'your': {
                  'terminal': {}
              }
          })
      ])
  }

  tr = LeftAligned()
  print(tr(tree))


Read the documentation at http://pythonhosted.org/asciitree
