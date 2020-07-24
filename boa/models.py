
class Scan(db.Model):
    """
    Stores information for a successful boa scan on an executable for
    output consumption as a report.
    """

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), unique=False, nullable=False)

    archive_files = db.Column(db.Integer)
    bytecode_files = db.Column(db.Integer)
    total_files = db.Column(db.Integer)
