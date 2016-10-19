

def increament_val(dbh, tabname, key, keyf='desc', valuef='data'):
    """
    Increaments the value of the key in tabname purely using sql query.
    final value of key in tabname will be tabname[keyf=key] + 1 
    """
    q = "update {tabname} set {valuef}=(select {valuef}+1 from {tabnme} "\
        "where desc=\"{key}\") where {keyf}=\"{key}\"".format(
            tabname=tabname, keyf=keyf, key=key, valuef=valuef
        )
    dbh.query(q)
