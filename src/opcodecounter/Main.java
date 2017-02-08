package opcodecounter;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class Main {

	public static void main(String[] args) {

		List<String> opcodes = new ArrayList<String>();
		HashMap<String, Integer> malOpcodes = new HashMap<String, Integer>();
		HashMap<String, Integer> benOpcodes = new HashMap<String, Integer>();
		File malDir = new File("C:\\Users\\ColbyAdmin\\Desktop\\Test\\Malware");
		File benDir = new File("C:\\Users\\ColbyAdmin\\Desktop\\Test\\Benign");
		File[] malFiles = malDir.listFiles();
		File[] benFiles = benDir.listFiles();
		int malAmount = 0, benAmount = 0;
		
		

		// Loop through Malware
		for(File f: malFiles) {
			try {
				BufferedReader br = new BufferedReader(new FileReader(f));
				for (String line = br.readLine(); line != null; line = br.readLine()) {
					if(!opcodes.contains(line)) {
						opcodes.add(line);
					}
					if(malOpcodes.containsKey(line)) {
						int currentVal = malOpcodes.get(line);
						currentVal++;
						malOpcodes.put(line, currentVal);
					} else {
						malOpcodes.put(line, 1);
					}
					malAmount++;
				}
				br.close();
			} catch (FileNotFoundException e) {
				System.out.println("Error opening file: " + f.getAbsolutePath());
			} catch (IOException e) {
				System.out.println("Error reading from file: " + f.getAbsolutePath());
			}
		}

		// Loop through Benign
		for(File f: benFiles) {
			try {
				BufferedReader br = new BufferedReader(new FileReader(f));
				for (String line = br.readLine(); line != null; line = br.readLine()) {
					if(!opcodes.contains(line)) {
						opcodes.add(line);
					}
					if(benOpcodes.containsKey(line)) {
						int currentVal = benOpcodes.get(line);
						currentVal++;
						benOpcodes.put(line, currentVal);
					} else {
						benOpcodes.put(line, 1);
					} 
					benAmount++;
				}
				br.close();
			} catch (FileNotFoundException e) {
				System.out.println("Error opening file: " + f.getAbsolutePath());
			} catch (IOException e) {
				System.out.println("Error reading from file: " + f.getAbsolutePath());
			}
		}
		
		// Calculate and Output results
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter("C:\\Users\\ColbyAdmin\\Desktop\\Test\\results.txt"));
			for(String s : opcodes) {
				int opMal, opBen;
				bw.write(s);
				bw.write(" ");
				if(malOpcodes.containsKey(s)){
					opMal = malOpcodes.get(s);
					bw.write(String.valueOf(opMal));
					bw.write(" ");
				} else {
					opMal = 0;
					bw.write(String.valueOf(0));
					bw.write(" ");
				}
				if(benOpcodes.containsKey(s)){
					opBen = benOpcodes.get(s);
					bw.write(String.valueOf(opBen));
					bw.write(" ");
				} else {
					opBen = 0;
					bw.write(String.valueOf(0));
					bw.write(" ");
				}
				double value = theEquation3(opMal, opBen, malAmount, benAmount, malFiles.length, benFiles.length);
				bw.write(Double.toString(value));
				bw.newLine();
			}
			bw.close();
		} catch (IOException e) {
			System.out.println("Error writing to source file.");
		}
	}
	
	/*
	 * First interpretation of the mutual information equation. This version uses the frequency that the opcode appears in malware and the frequency it
	 * appears in benign files instead of just relying on the total. Marginal probability is not used.
	 */
	public static double theEquation1(int opMal, int opBen, int malAmount, int benAmount, int malFiles, int benFiles) {
		double pOM, pOB, pO, pM, pB, value;
		pOM = (double)opMal/malAmount;
		pOB = (double)opBen/benAmount;
		pO = (double)(opMal + opBen)/(malAmount + benAmount);
		pM = (double)malFiles/(malFiles + benFiles);
		pB = (double)benFiles/(malFiles + benFiles);

		System.out.println(pOM + " " + pOB + " " + pO + " " + pM + " " + pB);

		value = pOM * Math.log((pOM/(pM * pO)));
		System.out.println(value);
		value += (1 - pOM) * Math.log(((1 - pOM)/(pM * (1 - pO))));
		System.out.println(value);
		value += pOB * Math.log((pOB/(pB * pO)));
		System.out.println(value);
		value += (1 - pOB) * Math.log(((1 - pOB)/(pB * (1 - pO))));
		System.out.println(value);
		return value;	
	}
	
	/*
	 * This is the interpretation of the equation that relies on marginal probability and the frequency that a given opcode appears across all files and
	 * not just by category. 
	 */
	public static double theEquation2(int opMal, int opBen, int malAmount, int benAmount, int malFiles, int benFiles) {
		double opcodeProb, malProb, benProb, value;
		opcodeProb = (double)(opMal + opBen)/(malAmount + benAmount);
		malProb = (double)malFiles/(malFiles + benFiles);
		benProb = (double)benFiles/(malFiles + benFiles);
		
		value = (opcodeProb * malProb) * Math.log((opcodeProb * malProb)/(marginalProb(malProb, opcodeProb, (1 - opcodeProb)) * marginalProb(opcodeProb, malProb, benProb)));
		//System.out.println(value);
		value += ((1 - opcodeProb) * malProb) * Math.log(((1 - opcodeProb) * malProb)/(marginalProb(malProb, opcodeProb, (1 - opcodeProb)) * marginalProb((1- opcodeProb), malProb, benProb)));
		//System.out.println(value);
		value += (opcodeProb * benProb) * Math.log((opcodeProb * benProb)/(marginalProb(benProb, opcodeProb, (1 - opcodeProb)) * marginalProb(opcodeProb, malProb, benProb)));
		//System.out.println(value);
		value += ((1 - opcodeProb) * benProb) * Math.log(((1 - opcodeProb) * benProb)/(marginalProb(benProb, opcodeProb, (1 - opcodeProb)) * marginalProb((1- opcodeProb), malProb, benProb)));
		//System.out.println(value);
		return value;	
	}
	
	public static double theEquation3(int opMal, int opBen, int malAmount, int benAmount, int malFiles, int benFiles) {
		double opcodeProb, malProb, benProb, value;
		opcodeProb = (double)(opMal + opBen)/(malAmount + benAmount);
		malProb = (double)malFiles/(malFiles + benFiles);
		benProb = (double)benFiles/(malFiles + benFiles);
		
		value = (opcodeProb * malProb) * Math.log(((opcodeProb * malProb)/(marginalProb(malProb, opcodeProb, (1 - opcodeProb)) * marginalProb(opcodeProb, malProb, benProb))));
		//System.out.println(value);
		value += (1 - opcodeProb * malProb) * Math.log((1 - opcodeProb * malProb)/(marginalProb(malProb, opcodeProb, (1 - opcodeProb)) * marginalProb((1- opcodeProb), malProb, benProb)));
		//System.out.println(value);
		value += (opcodeProb * benProb) * Math.log(((opcodeProb * benProb)/(marginalProb(benProb, opcodeProb, (1 - opcodeProb)) * marginalProb(opcodeProb, malProb, benProb))));
		//System.out.println(value);
		value += (1 - opcodeProb * benProb) * Math.log((1 - opcodeProb * benProb)/(marginalProb(benProb, opcodeProb, (1 - opcodeProb)) * marginalProb((1- opcodeProb), malProb, benProb)));
		//System.out.println(value);
		return value;	
	}
	
	public static double marginalProb(double x, double y1, double y2) {
		double value;
		value = x * y1;
		value += (x * y2);
		return value;
	}
}