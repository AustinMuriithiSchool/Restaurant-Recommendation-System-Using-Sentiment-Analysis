import spacy
nlp = spacy.load("en_core_web_sm")

def extract_location(query):
    doc = nlp(query)
    for ent in doc.ents:
        if ent.label_ == "GPE":  # Geo-Political Entity (city, country)
            return ent.text
    return None
