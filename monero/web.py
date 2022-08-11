import random
import requests

from io import BytesIO
from node import node
from network import CHAIN_PORT, validate_port
from flask import Flask, send_file, request

app = Flask(__name__)


# Support function
@app.route('/height')
def height():
    return str(len(node.chain.blocks))

@app.route('/queue')
def queue():
    return str(len(node.chain.txs))

# node function
@app.route('/nodes')
def nodes():
    nodes = list(node.nodes)
    return ','.join(nodes)

@app.route('/register', methods = ['POST'])
def register():
    ip = request.form.get("ip")
    try:
        node.registerNodes(ip)
        return 'IP: {} is registered'.format(ip)
    except:
        return 'Register fails'

# Wallet function
@app.route('/address')
def address():
    return node.address()

@app.route('/balance')
def balance():
    return str(node.balance())

@app.route('/mine')
def mine():
    node.mine()
    return "mined a new block"

@app.route('/transfer', methods = ['POST'])
def transfer():
    addr = request.form.get("address")
    amount = int(request.form.get("amount"))
    fee = int(request.form.get("fee"))
    node.transfer(addr, amount, fee)
    return "{} sent to {} with {} fee".format(amount, addr, fee)

# Chain function
@app.route('/chain')
def chain():
    return send_file(
        BytesIO(node.getChainInBytes()),
        attachment_filename='chain.dat',
        mimetype='application/octet-stream'
    )

@app.route('/tx')
def tx():
    return send_file(
        BytesIO(node.getTxInBytes()),
        attachment_filename='tx.dat',
        mimetype='application/ectet-stream'
    )

@app.route('/sync')
def sync():
    # validate all nodes
    node.nodes = set([ i for i in list(node.nodes) if validate_port(i) ])

    # if nodes len <= 5: select all nodes
    dest = list(node.nodes)
    # if nodes len > 5: select 5 random nodes
    if len(dest) > 5:
        random.shuffle(dest)
        dest = dest[0:5]

    # for each node
    for dest in dest:
        url = "http://{}:{}/".format(dest, CHAIN_PORT)
        nodes_response = requests.get(url + 'nodes')
        ip =  nodes_response.content.decode().split(',')
        node.registerNodes(ip)

        chain_response = requests.get(url + 'chain')
        chainInBytes = chain_response.content
        node.replaceChainInBytes(BytesIO(chainInBytes))

        tx_response = requests.get(url + 'tx')
        txInBytes = tx_response.content
        node.replaceTxInBytes(BytesIO(txInBytes))

        return 'node synced to network'


if __name__ == '__main__':
      app.run(host='0.0.0.0', port=CHAIN_PORT)