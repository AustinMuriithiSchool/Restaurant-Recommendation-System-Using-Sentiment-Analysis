import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os, re, json, argparse, random
from typing import List, Dict
import numpy as np
from sklearn.metrics import f1_score, precision_recall_fscore_support
from datasets import load_dataset, DatasetDict
from transformers import (
    AutoTokenizer, AutoConfig, AutoModelForSequenceClassification,
    DataCollatorWithPadding, Trainer, TrainingArguments
)

# ---------- aspect keywords (edit for your context) ----------
ASPECT_SYNONYMS: Dict[str, List[str]] = {
    # 1) FOOD & TASTE
    "food": [
        "food","meal","meat","dish","cuisine","taste","flavor","flavour","aroma","smell","presentation","plating",
        "fresh","stale","delicious","tasty","yummy","bland","spicy","salty","sweet","sour","bitter",
        "juicy","tender","seafood","crispy","crunchy","dry","oily","greasy","overcooked","undercooked","burnt","raw",
        "ingredients","recipe","specialty","pilau","nyama","nyama choma","ugali","chapati","fish","chicken","beef","pizza","burger",
        "fries","chips","bbq","grilled","fried","boiled","roast","soup","dessert","cake","pastry","sandwich","biryani"
    ],

    # 2) DRINKS & BAR
    "drinks": [
        "drink","drinks","beverage","cocktail","cocktails","mocktail","juice","smoothie","soda","water","milkshake",
        "coffee","tea","espresso","latte","cappuccino","mocha","beer","wine","whiskey","vodka","rum","gin",
        "cider","spirits","liquor","bar","bartender","brewed","chilled","iced","hot drink","alcohol","non-alcoholic"
    ],

    # 3) SERVICE & STAFF (incl. behavior)
    "service": [
        "service","customer service","server","waiter","waitress","attendant","staff","team","host","hostess",
        "bartender","cashier","reception","manager","management","professional","polite","courteous","friendly",
        "welcoming","attentive","responsive","helpful","rude","impolite","unhelpful","hospitality","attitude",
        "greeting","smile","care","responsiveness","follow-up"
    ],

    # 4) SPEED & WAIT TIME
    "speed_wait": [
        "speed","fast","slow","quick","prompt","timely","delay","late","on time","wait time","waiting","queue",
        "line","service time","response time","order speed","delivery time","lag","rush"
    ],

    # 5) PRICE & VALUE
    "price_value": [
        "price","priced","cost","expensive","pricey","cheap","affordable","reasonable","budget","value",
        "worth","money’s worth","bang for buck","deal","bargain","discount","offer","special","charge",
        "payment","bill","receipt","cost-effective"
    ],

    # 6) ATMOSPHERE (ambience + decor + music + noise + temperature)
    "atmosphere": [
        "ambience","ambiance","atmosphere","vibe","mood","environment","setting","cozy","romantic","intimate",
        "lively","calm","peaceful","crowded","spacious","cramped","lighting","dim","bright","decor","interior",
        "design","aesthetic","theme","furniture","layout","arrangement","music","playlist","dj","band","live music",
        "sound","noise","noisy","quiet","volume","speaker","temperature","hot","cold","warm","chilly",
        "air conditioning","ac","ventilation","draft","family","kid"
    ],

    # 7) CLEANLINESS & HYGIENE (incl. restrooms)
    "cleanliness_hygiene": [
        "clean","cleanliness","dirty","filthy","spotless","neat","tidy","organized","messy","hygiene","hygienic",
        "sanitary","sanitized","disinfected","odor","smell","garbage","trash","waste","kitchen hygiene",
        "restroom","toilet","bathroom","washroom","urinal","sink","soap","tissue","restroom smell","restroom hygiene"
    ],

    # 8) LOCATION & ACCESS (incl. parking & accessibility)
    "location_access": [
        "location","area","neighborhood","nearby","close","far","distance","around","corner","landmark",
        "downtown","uptown","street","road","avenue","plaza","mall","view","scenery","directions","map",
        "accessible","accessibility","wheelchair","ramp","stairs","elevator","lift","entrance","exit","signage",
        "parking","car park","valet","garage","spot","space","traffic","convenience","transport","bus","taxi","uber"
    ],

    # 9) MENU & VARIETY (incl. dietary options & customization)
    "menu_variety": [
        "menu","options","variety","selection","choices","items","offerings","specials","seasonal","combo",
        "set menu","a la carte","chefs special","recommended","new dish","availability","out of stock",
        "vegetarian","vegan","gluten-free","halal","kosher","lactose-free","keto","allergy","customize","customization"
    ],

    # 10) PORTION SIZE & SATIETY
    "portion_size": [
        "portion","portion size","serving","serving size","share","quantity","amount","big","small","huge","tiny",
        "generous","filling","enough","adequate","light","hearty","plate"
    ],

    # 11) DELIVERY & TAKEOUT (incl. packaging)
    "delivery_takeout": [
        "delivery","deliver","takeaway","take-out","takeout","pick-up","pickup","order online","app","website",
        "rider","driver","courier","on time","late delivery","tracking","status","packaging","package","parcel",
        "container","sealed","leak","spilled","insulated","well packed","poorly packed","glovo","ubereats","jumia food",
        "doordash","grubhub","foodpanda"
    ],

    # 12) FACILITIES & CONNECTIVITY (incl. Wi-Fi, power)
    "facilities_connectivity": [
        "facility","facilities","wifi","wi-fi","internet","network","signal","speed","password","login","charging",
        "socket","power outlet","plug","rest area","wash area","handwash","kids area","play area","outdoor seating",
        "smoking area","non-smoking"
    ],

    # 13) SAFETY & SECURITY
    "safety_security": [
        "safety","secure","security","unsafe","guard","bouncer","harassment","robbery","safe","night safety",
        "lighting outside","cctv","surveillance","fire exit","safety measures","first aid"
    ],

    # 14) EVENTS & ENTERTAINMENT
    "events_entertainment": [
        "event","events","party","celebration","birthday","anniversary","gathering","meeting","function","live","performance","karaoke","game","football","big screen","projector","screening","entertainment","venue hire"
    ],

    # 15) OVERALL EXPERIENCE & RECOMMENDATION
    "overall_experience": [
        "experience","overall","general","impression","satisfaction","delighted","happy","unhappy","disappointed",
        "enjoyment","memorable","recommend","recommendation","will return","come back","first time","regular",
        "expectation","exceeded","met expectations","did not meet","feedback","review","opinion"
    ],
}
SENTIMENT_LABELS = ["negative", "positive"]

def map_rating_to_sentiment(r):
    try:
        r = float(r)
    except:
        return None
    if r <= 2.0:
        return "negative"
    if r >= 3.0:
        return "positive"

def build_aspect_vector(text: str, aspects: List[str], syns: Dict[str, List[str]]) -> List[int]:
    if not isinstance(text, str): return [0]*len(aspects)
    t = " " + text.lower() + " "
    vec = [0]*len(aspects)
    for i, a in enumerate(aspects):
        for k in syns.get(a, [a]):
            k = k.lower()
            if re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", t):
                vec[i] = 1
                break
    return vec

def compute_metrics_sent(eval_pred):
    from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    cm = confusion_matrix(labels, preds)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average=None)
    precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(labels, preds, average="macro")
    return {
        "accuracy": float((preds == labels).mean()),
        "f1_macro": f1_macro,
        "precision_macro": precision_macro,
        "recall_macro": recall_macro,
        "confusion_matrix": cm.tolist(),
        "precision_per_class": precision.tolist(),
        "recall_per_class": recall.tolist(),
        "f1_per_class": f1.tolist()
    }

def compute_metrics_aspects(eval_pred):
    logits, labels = eval_pred
    probs = 1 / (1 + np.exp(-logits))  # sigmoid
    preds = (probs >= 0.5).astype(int)
    p_micro, r_micro, f_micro, _ = precision_recall_fscore_support(labels, preds, average="micro", zero_division=0)
    p_macro, r_macro, f_macro, _ = precision_recall_fscore_support(labels, preds, average="macro", zero_division=0)
    return {
        "precision_micro": p_micro, "recall_micro": r_micro, "f1_micro": f_micro,
        "precision_macro": p_macro, "recall_macro": r_macro, "f1_macro": f_macro
    }

def main():
    def save_aspect_metrics_pdf(metrics, output_path):
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
        c.setFont("Helvetica", 12)
        y = height - 40
        c.drawString(40, y, "Aspect Model Test Metrics")
        y -= 30
        c.drawString(40, y, f"Loss: {metrics['eval_loss']:.4f}")
        y -= 20
        c.drawString(40, y, f"Micro Precision: {metrics['eval_precision_micro']:.4f}")
        y -= 20
        c.drawString(40, y, f"Micro Recall: {metrics['eval_recall_micro']:.4f}")
        y -= 20
        c.drawString(40, y, f"Micro F1: {metrics['eval_f1_micro']:.4f}")
        y -= 30
        c.drawString(40, y, f"Macro Precision: {metrics['eval_precision_macro']:.4f}")
        y -= 20
        c.drawString(40, y, f"Macro Recall: {metrics['eval_recall_macro']:.4f}")
        y -= 20
        c.drawString(40, y, f"Macro F1: {metrics['eval_f1_macro']:.4f}")
        c.save()
    def save_sentiment_metrics_pdf(metrics, output_path):
        # Create PDF
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
        c.setFont("Helvetica", 12)
        y = height - 40
        c.drawString(40, y, "Sentiment Model Test Metrics")
        y -= 30
        c.drawString(40, y, f"Accuracy: {metrics['eval_accuracy']:.4f}")
        y -= 20
        c.drawString(40, y, f"F1 Macro: {metrics['eval_f1_macro']:.4f}")
        y -= 20
        c.drawString(40, y, f"Precision Macro: {metrics['eval_precision_macro']:.4f}")
        y -= 20
        c.drawString(40, y, f"Recall Macro: {metrics['eval_recall_macro']:.4f}")
        y -= 30
        c.drawString(40, y, "Precision per class: " + ', '.join([f'{v:.4f}' for v in metrics['eval_precision_per_class']]))
        y -= 20
        c.drawString(40, y, "Recall per class: " + ', '.join([f'{v:.4f}' for v in metrics['eval_recall_per_class']]))
        y -= 20
        c.drawString(40, y, "F1 per class: " + ', '.join([f'{v:.4f}' for v in metrics['eval_f1_per_class']]))
        y -= 30
    # Confusion matrix as image
        cm = metrics['eval_confusion_matrix']
        fig, ax = plt.subplots()
        im = ax.imshow(cm, cmap='Blues')
        ax.set_title('Confusion Matrix')
        ax.set_xlabel('Predicted')
        ax.set_ylabel('True')
        plt.colorbar(im, ax=ax)
        for i in range(len(cm)):
            for j in range(len(cm[0])):
                ax.text(j, i, str(cm[i][j]), ha='center', va='center', color='black')
        plt.tight_layout()
        img_path = output_path.replace('.pdf', '_cm.png')
        plt.savefig(img_path)
        plt.close(fig)
        # Add image to PDF
        y -= 180
        c.drawImage(img_path, 40, y, width=300, height=150)
        c.save()

    ap = argparse.ArgumentParser()
    ap.add_argument("--csv_path", type=str, required=True)
    ap.add_argument("--model_name", type=str, default="distilroberta-base")  # switched default
    ap.add_argument("--output_dir", type=str, default="./outputs_distilroberta_base_restaurant")  # switched default
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch_size", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--max_length", type=int, default=256)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    # seeding
    random.seed(args.seed)
    np.random.seed(args.seed)
    try:
        import torch
        torch.manual_seed(args.seed)
    except Exception:
        pass

    assert os.path.exists(args.csv_path), f"CSV not found: {args.csv_path}"

    # load and sanitize
    ds_all = load_dataset("csv", data_files={"data": args.csv_path})["data"]
    needed = {"Review","Rating"}
    missing = [c for c in needed if c not in ds_all.column_names]
    if missing: raise ValueError(f"CSV missing columns {missing}. Found: {ds_all.column_names}")

    def _prep(ex):
        lab = map_rating_to_sentiment(ex["Rating"])
        return {
            "text": "" if ex["Review"] is None else str(ex["Review"]),
            "labels_sent": SENTIMENT_LABELS.index(lab) if lab in SENTIMENT_LABELS else -1,
        }
    ds_all = ds_all.map(_prep, remove_columns=[c for c in ds_all.column_names if c not in {"Review","Rating"}])
    ds_all = ds_all.filter(lambda x: len(x["text"].strip())>0 and x["labels_sent"]>=0)

    # weak aspect targets
    aspect_labels = list(ASPECT_SYNONYMS.keys())
    ds_all = ds_all.map(lambda ex: {"labels_aspects": build_aspect_vector(ex["text"], aspect_labels, ASPECT_SYNONYMS)})

    # splits: test 10% ; from remaining, val 10%
    ds_tmp = ds_all.train_test_split(test_size=0.1, seed=args.seed)
    ds_tr_val = ds_tmp["train"].train_test_split(test_size=0.1, seed=args.seed)
    ds = DatasetDict(train=ds_tr_val["train"], validation=ds_tr_val["test"], test=ds_tmp["test"])

    # tokenize
    tokenizer = AutoTokenizer.from_pretrained(args.model_name, use_fast=True)
    def _tok(batch): return tokenizer(batch["text"], truncation=True, max_length=args.max_length)
    tokenized = ds.map(_tok, batched=True, remove_columns=["text"])
    collator = DataCollatorWithPadding(tokenizer=tokenizer)

    os.makedirs(args.output_dir, exist_ok=True)
    with open(os.path.join(args.output_dir, "label_info.json"), "w") as f:
        json.dump({"sentiment_labels": SENTIMENT_LABELS, "aspect_labels": aspect_labels}, f, indent=2)

    # -------- sentiment model --------
    cfg_s = AutoConfig.from_pretrained(
        args.model_name, num_labels=len(SENTIMENT_LABELS),
        id2label={i:l for i,l in enumerate(SENTIMENT_LABELS)},
        label2id={l:i for i,l in enumerate(SENTIMENT_LABELS)}
    )
    model_s = AutoModelForSequenceClassification.from_pretrained(args.model_name, config=cfg_s)
    ds_s = DatasetDict({
        split: tokenized[split].remove_columns(
            [c for c in tokenized[split].column_names if c not in {"input_ids","attention_mask","labels_sent"}]
        ).rename_column("labels_sent","labels")
        for split in ["train","validation","test"]
    })
    args_s = TrainingArguments(
        output_dir=os.path.join(args.output_dir,"sentiment"),
        learning_rate=args.lr,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        num_train_epochs=args.epochs,
        eval_strategy="epoch",     # fixed name
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1_macro",
        seed=args.seed,
        logging_steps=50,
        report_to="none"
    )
    trainer_s = Trainer(
        model=model_s, args=args_s,
        train_dataset=ds_s["train"], eval_dataset=ds_s["validation"],
        tokenizer=tokenizer, data_collator=collator,
        compute_metrics=compute_metrics_sent
    )
    trainer_s.train(resume_from_checkpoint=True)
    sent_metrics = trainer_s.evaluate(ds_s["test"])
    print("[Sentiment] Test:")
    print("Accuracy:", sent_metrics["eval_accuracy"])
    print("F1 Macro:", sent_metrics["eval_f1_macro"])
    print("Precision Macro:", sent_metrics["eval_precision_macro"])
    print("Recall Macro:", sent_metrics["eval_recall_macro"])
    print("Confusion Matrix:\n", np.array(sent_metrics["eval_confusion_matrix"]))
    print("Precision per class:", sent_metrics["eval_precision_per_class"])
    print("Recall per class:", sent_metrics["eval_recall_per_class"])
    print("F1 per class:", sent_metrics["eval_f1_per_class"])
    # Save metrics to PDF
    pdf_path = os.path.join(args.output_dir, "sentiment_metrics.pdf")
    save_sentiment_metrics_pdf(sent_metrics, pdf_path)
    trainer_s.save_model(); tokenizer.save_pretrained(args_s.output_dir)

    # -------- aspect model (multi-label) --------
    cfg_a = AutoConfig.from_pretrained(
        args.model_name, num_labels=len(aspect_labels),
        problem_type="multi_label_classification",
        id2label={i:l for i,l in enumerate(aspect_labels)},
        label2id={l:i for i,l in enumerate(aspect_labels)}
    )
    model_a = AutoModelForSequenceClassification.from_pretrained(args.model_name, config=cfg_a)

    def _mk_aspect(split):
        cols = tokenized[split].column_names
        keep = {"input_ids","attention_mask","labels_aspects"}
        return tokenized[split].remove_columns([c for c in cols if c not in keep]).map(
            lambda ex: {"labels": [float(v) for v in ex["labels_aspects"]]}  # list of floats (safer)
        )
    ds_a = DatasetDict({split: _mk_aspect(split) for split in ["train","validation","test"]})

    args_a = TrainingArguments(
        output_dir=os.path.join(args.output_dir,"aspects"),
        learning_rate=args.lr,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        num_train_epochs=args.epochs,
        eval_strategy="epoch",     # fixed name
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1_micro",
        seed=args.seed,
        logging_steps=50,
        report_to="none"
    )
    trainer_a = Trainer(
        model=model_a, args=args_a,
        train_dataset=ds_a["train"], eval_dataset=ds_a["validation"],
        tokenizer=tokenizer, data_collator=collator,
        compute_metrics=compute_metrics_aspects
    )
    trainer_a.train(resume_from_checkpoint=True)
    aspect_metrics = trainer_a.evaluate(ds_a["test"])
    print("[Aspects] Test:", aspect_metrics)
    pdf_path_aspect = os.path.join(args.output_dir, "aspect_metrics.pdf")
    save_aspect_metrics_pdf(aspect_metrics, pdf_path_aspect)
    trainer_a.save_model(); tokenizer.save_pretrained(args_a.output_dir)

    print("Done ->", args.output_dir, "| subfolders: sentiment/, aspects/, label_info.json")

if __name__ == "__main__":
    main()
