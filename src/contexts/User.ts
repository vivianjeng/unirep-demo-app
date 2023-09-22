import { createContext } from 'react'
import { makeAutoObservable } from 'mobx'
import {
    IncrementalMerkleTree,
    genEpochKey,
    genStateTreeLeaf,
    stringifyBigInts,
} from '@unirep/utils'
import { CircuitConfig } from '@unirep/circuits'
import { Identity } from '@semaphore-protocol/identity'
import { DataProof } from './DataProof'
import prover from './prover'
const {
    FIELD_COUNT,
    REPL_NONCE_BITS,
    SUM_FIELD_COUNT,
    NUM_EPOCH_KEY_NONCE_PER_EPOCH,
    STATE_TREE_DEPTH,
} = CircuitConfig.default

class User {
    currentEpoch: number = 0
    latestTransitionedEpoch: number = 0
    hasSignedUp: boolean = false
    data: bigint[] = Array(FIELD_COUNT).fill(BigInt(0))
    provableData: bigint[] = Array(FIELD_COUNT).fill(BigInt(0))
    provider: any
    startTimestamp: number = 0
    epochLength: number = 300
    attesterId: string = '1234'
    id: Identity = new Identity()

    constructor() {
        makeAutoObservable(this)
        this.load()
    }

    load() {
        const id = localStorage.getItem('id')
        if (!id) {
            localStorage.setItem('id', this.id.toString())
        } else {
            this.id = new Identity(id)
        }
        for (let i = 0; i < this.fieldCount; i++) {
            const data = localStorage.getItem(`data${i}`)
            this.data[i] = data ? BigInt(data) : BigInt(0)
            const provableData = localStorage.getItem(`provableData${i}`)
            this.provableData[i] = provableData
                ? BigInt(provableData)
                : BigInt(0)
        }
    }

    get calEpoch() {
        const currentTimestamp = Math.floor(+new Date() / 1000)
        if (!this.startTimestamp) {
            const _timestamp = localStorage.getItem('startTimestamp')
            if (_timestamp) {
                this.startTimestamp = Number(_timestamp)
            } else {
                this.startTimestamp = Math.floor(+new Date() / 1000)
                localStorage.setItem(
                    'startTimestamp',
                    this.startTimestamp.toString(),
                )
            }
        }
        return Math.max(
            0,
            Math.floor(
                (currentTimestamp - this.startTimestamp) / this.epochLength,
            ),
        )
    }

    get calRemainingTime() {
        const epoch = this.calEpoch
        const timestamp = Math.floor(+new Date() / 1000)
        const epochEnd = this.startTimestamp + (epoch + 1) * this.epochLength
        return Math.max(0, epochEnd - timestamp)
    }

    get fieldCount() {
        return FIELD_COUNT
    }

    get sumFieldCount() {
        return SUM_FIELD_COUNT
    }

    get replNonceBits() {
        return REPL_NONCE_BITS
    }

    get numEpochKeyNoncePerEpoch() {
        return NUM_EPOCH_KEY_NONCE_PER_EPOCH
    }

    epochKey(nonce: number) {
        const epoch = this.calEpoch
        const key = genEpochKey(this.id.secret, this.attesterId, epoch, nonce)
        return `0x${key.toString(16)}`
    }

    signup() {
        this.hasSignedUp = true
        this.latestTransitionedEpoch = this.calEpoch
    }

    requestData(reqData: { [key: number]: string | number }) {
        for (const key of Object.keys(reqData)) {
            if (reqData[+key] === '') {
                delete reqData[+key]
                continue
            }
        }
        if (Object.keys(reqData).length === 0) {
            throw new Error('No data in the attestation')
        }
        for (const key of Object.keys(reqData)) {
            if (+key < SUM_FIELD_COUNT) {
                this.data[+key] += BigInt(reqData[+key])
            } else {
                this.data[+key] =
                    BigInt(reqData[+key]) << BigInt(this.replNonceBits)
            }
            localStorage.setItem(`data${key}`, this.data[+key].toString())
        }
    }

    stateTransition() {
        for (let i = 0; i < this.fieldCount; i++) {
            this.provableData[i] = this.data[i]
            localStorage.setItem(
                `provableData${i}`,
                this.provableData[i].toString(),
            )
        }
        this.latestTransitionedEpoch = this.calEpoch
    }

    async proveData(data: { [key: number]: string | number }) {
        const epoch = this.calEpoch
        const stateTree = new IncrementalMerkleTree(STATE_TREE_DEPTH)
        const leaf = genStateTreeLeaf(
            this.id.secret,
            this.attesterId,
            epoch,
            this.provableData,
        )
        stateTree.insert(leaf)
        const index = stateTree.indexOf(leaf)
        const stateTreeProof = stateTree.createProof(index)
        const provableData = this.provableData
        const values = Array(this.fieldCount).fill(0)
        for (let [key, value] of Object.entries(data)) {
            values[Number(key)] = value
        }
        const attesterId = this.attesterId
        const circuitInputs = stringifyBigInts({
            identity_secret: this.id.secret,
            state_tree_indexes: stateTreeProof.pathIndices,
            state_tree_elements: stateTreeProof.siblings,
            data: provableData,
            epoch: epoch,
            attester_id: attesterId,
            value: values,
        })
        const { publicSignals, proof } = await prover.genProofAndPublicSignals(
            'dataProof',
            circuitInputs,
        )
        const dataProof = new DataProof(publicSignals, proof, prover)
        const valid = await dataProof.verify()
        return stringifyBigInts({
            publicSignals: dataProof.publicSignals,
            proof: dataProof.proof,
            valid,
        })
    }
}

export default createContext(new User())
