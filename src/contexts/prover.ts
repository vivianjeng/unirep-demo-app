import * as snarkjs from 'snarkjs'
import { SnarkPublicSignals, SnarkProof } from '@unirep/utils'
import { Circuit } from '@unirep/circuits'
import vkey from '../../public/dataProof.vkey.json'

export default {
    verifyProof: async (
        circuitName: string | Circuit,
        publicSignals: SnarkPublicSignals,
        proof: SnarkProof,
    ) => {
        return snarkjs.groth16.verify(vkey, publicSignals, proof)
    },
    genProofAndPublicSignals: async (
        circuitName: string | Circuit,
        inputs: any,
    ) => {
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            inputs,
            `${circuitName}.wasm`,
            `${circuitName}.zkey`,
        )
        return { proof, publicSignals }
    },
    /**
     * Get vkey from default built folder `zksnarkBuild/`
     * @param name Name of the circuit, which can be chosen from `Circuit`
     * @returns vkey of the circuit
     */
    getVKey: async (name: string | Circuit) => {
        // return require(path.join(buildPath, `${name}.vkey.json`))
    },
}
