import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";

dotenv.config(); // Load .env

const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);

// All resident IDs
const residents = [
  "68bed73dcdf88515016bf7b1","68bed73dcdf88515016bf7b2","68bed740cdf88515016bf82c",
  "68bed740cdf88515016bf82d","68bed740cdf88515016bf82e","68bed740cdf88515016bf82f",
  "68bed740cdf88515016bf830","68bed740cdf88515016bf831","68bed740cdf88515016bf832",
  "68bed740cdf88515016bf833","68bed740cdf88515016bf834","68bed740cdf88515016bf835",
  "68bed740cdf88515016bf836","68bed740cdf88515016bf837","68bed740cdf88515016bf838",
  "68bed740cdf88515016bf839","68bed740cdf88515016bf83a","68bed740cdf88515016bf83b",
  "68bed740cdf88515016bf83c","68bed740cdf88515016bf83d","68bed740cdf88515016bf83e",
  "68bed740cdf88515016bf83f","68bed740cdf88515016bf840","68bed740cdf88515016bf841",
  "68bed740cdf88515016bf842","68bed740cdf88515016bf843","68bed740cdf88515016bf844",
  "68bed740cdf88515016bf845","68bed740cdf88515016bf846","68bed740cdf88515016bf847",
  "68bed740cdf88515016bf848","68bed740cdf88515016bf849","68bed740cdf88515016bf84a",
  "68bed740cdf88515016bf84b","68bed740cdf88515016bf84c","68bed740cdf88515016bf84d",
  "68bed740cdf88515016bf84e","68bed740cdf88515016bf84f","68bed740cdf88515016bf850",
  "68bed740cdf88515016bf851","68bed740cdf88515016bf852","68bed740cdf88515016bf853",
  "68bed740cdf88515016bf854","68bed740cdf88515016bf855","68bed740cdf88515016bf856",
  "68bed740cdf88515016bf857","68bed740cdf88515016bf858","68bed740cdf88515016bf859",
  "68bed740cdf88515016bf85a","68bed740cdf88515016bf85b","68bed740cdf88515016bf85c",
  "68bed740cdf88515016bf85d","68bed740cdf88515016bf85e","68bed740cdf88515016bf85f",
  "68bed740cdf88515016bf860","68bed740cdf88515016bf861","68bed740cdf88515016bf862",
  "68bed740cdf88515016bf863","68bed740cdf88515016bf864","68bed740cdf88515016bf865",
  "68bed740cdf88515016bf866","68bed740cdf88515016bf867","68bed740cdf88515016bf868",
  "68bed740cdf88515016bf869","68bed740cdf88515016bf86a","68bed740cdf88515016bf86b",
  "68bed740cdf88515016bf86c","68bed740cdf88515016bf86d","68bed740cdf88515016bf86e",
  "68bed740cdf88515016bf86f","68bed740cdf88515016bf870","68bed740cdf88515016bf871",
  "68bed740cdf88515016bf872","68bed740cdf88515016bf873","68bed740cdf88515016bf874",
  "68bed740cdf88515016bf875","68bed740cdf88515016bf876","68bed740cdf88515016bf877",
  "68bed740cdf88515016bf878","68bed740cdf88515016bf879","68bed740cdf88515016bf87a",
  "68bed740cdf88515016bf87b","68bed740cdf88515016bf87c","68bed740cdf88515016bf87d",
  "68bed740cdf88515016bf87e","68bed740cdf88515016bf87f","68bed740cdf88515016bf880",
  "68bed740cdf88515016bf881","68bed740cdf88515016bf882","68bed740cdf88515016bf883",
  "68bed740cdf88515016bf884","68bed740cdf88515016bf885","68bed740cdf88515016bf886",
  "68bed740cdf88515016bf887","68bed740cdf88515016bf888","68bed740cdf88515016bf889",
  "68bed740cdf88515016bf88a","68bed740cdf88515016bf88b","68bed740cdf88515016bf88c",
  "68bed740cdf88515016bf88d","68bed740cdf88515016bf88e","68bed740cdf88515016bf88f",
  "68bed740cdf88515016bf890","68bed740cdf88515016bf891","68bed740cdf88515016bf892",
  "68bed740cdf88515016bf893","68bed740cdf88515016bf894","68bed740cdf88515016bf895",
  "68bed740cdf88515016bf896","68bed740cdf88515016bf897","68bed740cdf88515016bf898",
  "68bed740cdf88515016bf899","68bed740cdf88515016bf89a","68bed740cdf88515016bf89b",
  "68bed740cdf88515016bf89c","68bed740cdf88515016bf89d","68bed740cdf88515016bf89e",
  "68bed740cdf88515016bf89f","68bed740cdf88515016bf8a0","68bed740cdf88515016bf8a1",
  "68bed740cdf88515016bf8a2","68bed740cdf88515016bf8a3","68bed740cdf88515016bf8a4"
];

// Other random data
const types = [
  "Barangay Clearance",
  "Barangay Indigency",
  "Good Moral",
  "Certificate of Residency",
  "Business Permit",
  "BARC Certificate"
];

const purposes = [
  "ANY LEGAL",
  "BURIAL ASSISTANCE",
  "EDUCATIONAL ASSISTANCE",
  "FINANCIAL ASSISTANCE",
  "MEDICAL ASSISTANCE",
  "BANK TRANSACTION",
  "BOARD EXAM",
  "CELCOR/ELECTRIC METER",
  "LCR",
  "LEGALIZATION",
  "LOCAL EMPLOYMENT",
  "PHILHEALTH",
  "POLICE CLEARANCE",
  "PRIME WATER",
  "SCHOOL REQUIREMENT",
  "SENIOR CITIZEN",
  "SOLO PARENT PWD",
  "TRAVEL ABROAD",
  "XXX"
];

const statuses = ["Approved","Released"];

const getRandom = arr => arr[Math.floor(Math.random() * arr.length)];
const getRandomInt = (min,max) => Math.floor(Math.random()*(max-min+1))+min;
const randomDate = (start,end) => new Date(start.getTime() + Math.random()*(end.getTime()-start.getTime()));

async function seedRequests() {
  try {
    await client.connect();
    const db = client.db("werequest25");
    const collection = db.collection("request");

    // Last year requests (2024)
    for(let month=0; month<12; month++){
      const count = getRandomInt(5,10);
      for(let i=0;i<count;i++){
        await collection.insertOne({
          tr: `DOC-2024${(month+1).toString().padStart(2,'0')}-${Math.random().toString(36).substring(2,8)}`,
          createdAt: randomDate(new Date(2024,month,1), new Date(2024,month+1,0,23,59,59)),
          updatedAt: new Date(),
          status: getRandom(statuses),
          archive:0,
          requestBy: new ObjectId(getRandom(residents)),
          requestFor: new ObjectId(getRandom(residents)),
          remarkMain:"",
          remarks:"",
          type:getRandom(types),
          qty:getRandomInt(1,3),
          purpose:getRandom(purposes),
          proof:""
        });
      }
    }

    // This year requests (2025)
    const now = new Date();
    for(let i=0;i<30;i++){
      await collection.insertOne({
        tr:`DOC-2025-${Math.random().toString(36).substring(2,8)}`,
        createdAt: randomDate(new Date(2025,0,1), now),
        updatedAt: new Date(),
        status:getRandom(statuses),
        archive:0,
        requestBy:new ObjectId(getRandom(residents)),
        requestFor:new ObjectId(getRandom(residents)),
        remarkMain:"",
        remarks:"",
        type:getRandom(types),
        qty:getRandomInt(1,3),
        purpose:getRandom(purposes),
        proof:""
      });
    }

    // Requests for today
    const today = new Date();
    for(let hour of [8,12,16,20]){
      await collection.insertOne({
        tr:`DOC-2025-TODAY-${Math.random().toString(36).substring(2,8)}`,
        createdAt:new Date(today.getFullYear(),today.getMonth(),today.getDate(),hour,getRandomInt(0,59),getRandomInt(0,59)),
        updatedAt:new Date(),
        status:getRandom(statuses),
        archive:0,
        requestBy:new ObjectId(getRandom(residents)),
        requestFor:new ObjectId(getRandom(residents)),
        remarkMain:"",
        remarks:"",
        type:getRandom(types),
        qty:getRandomInt(1,3),
        purpose:getRandom(purposes),
        proof:""
      });
    }

    console.log("Random requests seeded successfully!");
  } catch(err) {
    console.error(err);
  } finally {
    await client.close();
  }
}

seedRequests();
