# indivproj

## Running the tests
Run the script to extract the attack phrases and sentence <br>
`python <path to inference_originalFilter6_sentence_phrase_regex_YARA_temp.py> --entity-extraction-weight=<path to entity_ext.pt> --sentence-classification-weight=<path to sent_cls.pt> --input-doc=<path to test reports to be analysed> --save-path=<path to any .txt document to save printed extracted phrases/sentences>`

Then run the script to identify MITRE techniques <br>
`python <path to part2original_atkBert_append162b2c2_46_regexv11.py> --sentence_file=<path to the .txt file of --save_path when running the script to extract phrases and sentences> > <Any .txt file to print the results>`


