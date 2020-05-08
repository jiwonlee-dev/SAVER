/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;

import util.Util;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;

import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SubsetSumHashGadget;
import examples.gadgets.hash.SHA256Gadget;

public class voteSAVER_relation extends CircuitGenerator {

/********************* Vote Msg and random ***************************/
	private Wire[] input_s;

	private Wire[] pk_e;
	private Wire[] SK_id;

	/********************* MerkleTree ***************************/
	//private Wire[] publicRootWires;
	private Wire[] intermediateHasheWires;
	private Wire directionSelector;

	private int num_of_elector = 64;
	private int leafNumOfWords = 8;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;

	private MerkleTreePathGadget merkleTreeGadget;
	private SHA256Gadget sha2Gadget;

	public voteSAVER_relation(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
	}

	@Override
	protected void buildCircuit() {
		input_s = createInputWireArray(num_of_elector);
		pk_e = createInputWireArray(leafNumOfWords,"e");

		SK_id = createProverWitnessWireArray(leafNumOfWords,"sk_id");

		Wire[] skBits = new WireArray(SK_id).getBits(leafWordBitWidth).asArray();
		SubsetSumHashGadget subsetSumGadget = new SubsetSumHashGadget(skBits, false);
		Wire[] leafWires = subsetSumGadget.getOutputWires();

		directionSelector = createProverWitnessWire("Direction selector");
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");

		merkleTreeGadget = new MerkleTreePathGadget(directionSelector, leafWires, intermediateHasheWires,
				254, treeHeight);
		Wire[] actualRoot = merkleTreeGadget.getOutputWires();

		Wire[] sn_input = new Wire[16];
		for (int j = 0; j < 8; j++) {
			sn_input[j] = SK_id[j];
		}
		for (int j = 8; j < 16; j++) {
			sn_input[j] = pk_e[j-8];
		}
		Wire[] snBits = new WireArray(sn_input).getBits(leafWordBitWidth).asArray();
		subsetSumGadget = new SubsetSumHashGadget(snBits, false);
		Wire[] out = subsetSumGadget.getOutputWires();
		
		makeOutputArray(out, "sn");

		for(int i = 0; i < actualRoot.length; i++){
			actualRoot[i] = actualRoot[i];
		}

		makeOutputArray(actualRoot, "Computed Root");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		int i = 0;
		for(i = 0; i < num_of_elector; i ++){
			circuitEvaluator.setWireValue(input_s[i], 0);
		}
		for (i = 0; i < leafNumOfWords; i++) {
			circuitEvaluator.setWireValue(pk_e[i], Integer.MAX_VALUE);
			circuitEvaluator.setWireValue(SK_id[i], Integer.MAX_VALUE);
		}
		circuitEvaluator.setWireValue(directionSelector, 15);
		for (i = 0; i < hashDigestDimension*treeHeight; i++) {
			circuitEvaluator.setWireValue(intermediateHasheWires[i],  i);
		}
	}

	public static void main(String[] args) throws Exception {

		voteSAVER_relation generator = new voteSAVER_relation("voteSAVER_relation",16);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}
