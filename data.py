"""This file insert data into the database."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Catalog, Base, CatalogItem, User

engine = create_engine('sqlite:///catalogwithuser.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

"""A DBSession() instance establishes all conversations with the database
and represents a "staging zone" for all the objects loaded into the
database session object. Any change made against the objects in the
session won't be persisted into the database until you call
session.commit(). If you're not happy about the changes, you can
revert all of them back to the last commit by calling
session.rollback()
"""
session = DBSession()

# Create dummy user
User1 = User(name="Maged Mohamed", email="mmjazzar@ieee.org",
             picture='')
session.add(User1)
session.commit()

# Menu for UrbanBurger
catalog1 = Catalog(user_id=1, name="Baseball")

session.add(catalog1)
session.commit()

CatalogItem1 = CatalogItem(user_id=1,name = "Glove",
             description = "Catcher's mitt made by Wilson",
             catalog = catalog1)


session.add(CatalogItem1)
session.commit()


CatalogItem2 = CatalogItem(user_id=1,name = "Whistle",
             description = "To avoid bad practice, it's essential for a referee",
             catalog = catalog1)

session.add(CatalogItem2)
session.commit()

################################################3

catalog2 = Catalog(user_id=2, name = "Basketball")

session.add(catalog1)
session.commit()

CatalogItem1 = CatalogItem(user_id=2, name = "Ball",
            description = "Essential element for a good match",
            catalog=catalog2)


session.add(CatalogItem1)
session.commit()


CatalogItem2 = CatalogItem(user_id=2, name = "Jordan",
             description = "Yes, its true, if you wanna play like him, take this shoe",
             catalog=catalog2)

session.add(CatalogItem2)
session.commit()
print "all items are added successfully!"
