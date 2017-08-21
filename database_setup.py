import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import ConfigParser


Base = declarative_base()


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(75), nullable=False)


class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(String(1000))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    photo_path = Column(String(500))
    user_id = Column(Integer, ForeignKey('user.id'))

    @property
    def serialize(self):

        return {
                'name': self.name,
                'description': self.description,
                'id': self.id,
                'category': self.category.name,
                'image_location': self.photo_path,
               }


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    email = Column(String(200), nullable=False)


config = ConfigParser.RawConfigParser()
config.read('config.ini')
DB_URL = config.get('database', 'url')

engine = create_engine(DB_URL)
Base.metadata.create_all(engine)
