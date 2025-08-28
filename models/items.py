from . import db


class Item(db.Model):
    __tablename__ = "items"
    itemcode = db.Column(db.String(20), primary_key=True)
    description = db.Column(db.Text, nullable=False)
    warehouses = db.relationship("ItemWarehouse", back_populates="item", cascade="all, delete-orphan")