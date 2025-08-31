"""
Repository package for data access layers.

You can provide a custom implementation by setting the environment variable
`TITLES_REPOSITORY_IMPL` to a dotted path like:

    myapp.data.titles:PostgresTitleRepository

and ensuring that class implements the interface used by app.repositories.titles.
"""

