# pydantic-openapi-orm
A set of Pydantic models which can be instantiated from an OpenAPI 3 spec.

https://en.wikipedia.org/wiki/Object-relational_mapping
> Object-relational mapping (ORM, O/RM, and O/R mapping tool) in computer science is a programming technique for converting data between incompatible type systems using object-oriented programming languages.

So... I'm using this quote to justify stretching the usual db-centric understanding of what an ORM is.

In this case we're taking the loosely-typed JSON/YAML of an api schema and loading it into a set of Pydantic models which validate the input against the type system defined by the OpenAPI 3 specification, and return an OO object heirarchy.

Basically it's just a nicer way of working with an api schema than the pile of dictionaries you get from parsing the JSON or YAML.
