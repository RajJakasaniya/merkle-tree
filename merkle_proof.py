'''
Name        : Raj Jakasaniya
--------------------------------------
Student id  : 201501408
--------------------------------------
email-id    : raj.jakasaniya@gmail.com
--------------------------------------
python3 only
'''
from utils import *
import math
from node import Node
from merkle_tree import *

def merkle_proof(tx, merkle_tree):
    """Given a tx and a Merkle tree object, retrieve its list of tx's and
        parse through it to arrive at the minimum amount of information required
        to arrive at the correct block header. This does not include the tx
        itself.
        Return this data as a list; remember that order matters!
        """
    list_ts = merkle_tree.leaves
    num_ts = len(list_ts)
    t_id = merkle_tree.leaves.index(tx)
    
    if num_ts <= 1 or tx not in list_ts:
        return []
    return create(tx, [], merkle_tree._root, t_id)


def create(tx, trans, m_root, t_id):
    
    lc = m_root._left
    rc = m_root._right
    
    if type(lc) == str:
        if lc == tx:
            trans.append(Node('r', rc))
        elif rc == tx:
            trans.append(Node('l', lc))
        return trans
    else:
        if t_id % 2**(m_root.height) < 2**(m_root.height) / 2:
            trans.append(Node('r', rc.data))
            return create(tx, trans, lc, t_id)
        else:
            trans.append(Node('l', lc.data))
            return create(tx, trans, rc, t_id)


def verify_proof(tx, merkle_proof):
    """Given a Merkle proof - constructed via `merkle_proof(...)` - verify
        that the correct block header can be retrieved by properly hashing the tx
        along with every other piece of data in the proof in the correct order
        """
    lst_tx = [tx] + list(merkle_proof)[::-1]
    while len(lst_tx) > 1:
        if lst_tx[1].direction == 'r':
            lst_tx.insert(0, hash_data(lst_tx.pop(0) + lst_tx.pop(0).tx))
        else:
            lst_tx.insert(0, hash_data(lst_tx.pop(1).tx + lst_tx.pop(0)))
    return lst_tx[0]

    
