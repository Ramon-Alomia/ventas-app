from . import db


class ItemWarehouse(db.Model):
    __tablename__ = "item_warehouse"
    itemcode = db.Column(
        db.String(20),
        db.ForeignKey("items.itemcode", onupdate="CASCADE", ondelete="RESTRICT"),
        primary_key=True,
    )
    whscode = db.Column(
        db.String(20),
        db.ForeignKey("warehouses.whscode", onupdate="CASCADE", ondelete="RESTRICT"),
        primary_key=True,
    )
    price = db.Column(db.Numeric(12, 2))
    min_stock = db.Column(db.Integer)
    item = db.relationship("Item", back_populates="warehouses")