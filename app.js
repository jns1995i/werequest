require("dotenv").config();
const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const bodyParser = require("body-parser");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const engine = require("ejs-mate");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const ExcelJS = require("exceljs");
const PDFDocument = require("pdfkit");
const nodemailer = require('nodemailer');

const SECRET_KEY = "6LflzO4qAAAAAF4n0ABQ2YyHGPSA3RDjvtvFt1AQ";

const { v2: cloudinary } = require("cloudinary");
const { CloudinaryStorage } = require("multer-storage-cloudinary");

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

const fs = require('fs');
const uploadDir = 'public/uploads';

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}
// Use the file upload middleware


const app = express();
const PORT = process.env.PORT || 3025;

app.engine("ejs", engine);
app.set("view engine", "ejs");
app.use(express.json());

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));
app.use('/uploads', express.static('public/uploads'));


const store = new MongoDBStore({
    uri: process.env.MONGO_URI,
    collection: "sessions"
});

// New: Catch session store errors
store.on("error", function(error) {
    console.error("Session Store Error:", error);
});

app.set('trust proxy', 1);

app.use(session({
    secret: process.env.SESSION_SECRET || "your_secret_key",
    resave: false,
    saveUninitialized: false,
    store: store,
    cookie: {
        secure: process.env.NODE_ENV === "production",
        httpOnly: true
    }
}));

const client = new MongoClient(process.env.MONGO_URI);
let db;

client.connect()
    .then(() => {
        db = client.db();
        console.log("✅ Connected to MongoDB");
    })
    .catch(err => console.error("❌ MongoDB Connection Error:", err));

const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect("/");
    }
    next();
};

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "uploads",
    allowed_formats: ["jpg", "png", "jpeg", "webp"],
  },
});

const upload = multer({ storage });

const isLogin = async (req, res, next) => {
    try {
        if (!req.session.userId) {
            console.log("No session userId found");
            return res.redirect("/");
        }

        // Convert safely
        let userId = req.session.userId;
        if (typeof userId === "string" && ObjectId.isValid(userId)) {
            userId = new ObjectId(userId);
        }

        const user = await db.collection("resident").findOne({ _id: userId });
        if (!user) {
            console.log("User not found for ID:", userId);
            return res.redirect("/");
        }

        // ✅ Block archived or suspended users
        if (user.archive === 1 || user.archive === "1" || user.suspend === 1 || user.suspend === "1") {
            console.log("⛔ Blocked user tried to access:", user.username);
            req.session.destroy(() => {
                return res.render("index", { error: "Your account is suspended!" });
            });
            return; // stop further execution
        }

        // ✅ Fetch cases where this user is complainant or respondent (excluding archived/suspended)
        const cases = await db.collection("cases").find({
            $or: [
                { respondents: new ObjectId(user._id) },
                { complainants: new ObjectId(user._id) }
            ],
            archive: { $in: [0, "0"] },
            suspend: { $in: [0, "0"] } // global filter
        }).toArray();

      // ✅ 8. Fetch all residents involved in cases
        let persons = [];
        if (cases.length > 0) {
            const allPersonIds = [
                ...new Set(cases.flatMap(c => [...c.respondents, ...c.complainants]))
            ];
            persons = await db.collection("resident").find({
                _id: { $in: allPersonIds.map(id => new ObjectId(id)) }
            }).toArray();

            cases.forEach(c => {
                c.respondents = c.respondents.map(rid =>
                    persons.find(p => p._id.equals(rid)) || rid
                );
                c.complainants = c.complainants.map(rid =>
                    persons.find(p => p._id.equals(rid)) || rid
                );
            });
        }

        // ✅ Attach data to req and res.locals
        req.user = user;
        req.cases = cases;
        res.locals.user = user;
        res.locals.cases = cases;

        next();
    } catch (err) {
        console.error("Error in isLogin middleware:", err);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
    }
};


const sumDoc = async (req, res, next) => {
    try {
        if (!db) {
            console.error("❌ Database connection is not established yet.");
            return next(); // Prevent crashing, continue with the next middleware
        }

        const validStatuses = ["Processed", "Approved", "Success", "Processing"];

        // Fetch documents with valid statuses
        const documents = await db.collection("document").find({ status: { $in: validStatuses } }).toArray();

        if (!documents.length) {
            console.warn("⚠️ No valid documents found.");
        }

        // Count total valid documents
        const totalDocuments = documents.length;

        // Count occurrences per document type
        const documentTypeCounts = documents.reduce((acc, doc) => {
            if (doc.type) {
                acc[doc.type] = (acc[doc.type] || 0) + 1;
            }
            return acc;
        }, {});

        // Convert object to array and compute percentages
        const documentTypeStats = Object.entries(documentTypeCounts).map(([type, count]) => ({
            type,
            count,
            percentage: totalDocuments ? ((count / totalDocuments) * 100).toFixed(2) : "0"
        }));

        console.log("✅ sumDoc Results:", { totalDocuments, documentTypeStats });

        req.sumDoc = { documentTypeCounts: documentTypeStats, totalDocuments };
        res.locals.sumDoc = req.sumDoc;

    } catch (err) {
        console.error("❌ Error in sumDoc middleware:", err.message);
        req.sumDoc = { documentTypeCounts: [], totalDocuments: 0 };
        res.locals.sumDoc = req.sumDoc;
    }

    next();
};

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'johnniebre1995@gmail.com',
        pass: 'gswplydselmqjysq',
    },
    tls: {
      rejectUnauthorized: false, // 👈 this line tells Node.js to ignore self-signed cert errors
    },
  });
  

const sumReq = async (req, res, next) => {
    try {
        if (!db) {
            console.error("❌ Database connection is not established yet.");
            return next();
        }

        const validStatuses = ["Processed", "Approved", "Success", "Processing", "For Pickup", "Released"];

        // Count total requests directly from MongoDB
        const totalRequests = await db.collection("request").countDocuments({
            archive: { $in: [0, "0"] },
            status: { $in: validStatuses }
        });

        console.log("✅ sumReq Results:", { totalRequests });

        req.sumReq = { totalRequests }; // Attach to request
        res.locals.sumReq = req.sumReq; // Attach to locals (optional)

    } catch (err) {
        console.error("❌ Error in sumReq middleware:", err.message);
        req.sumReq = { totalRequests: 0 };
        res.locals.sumReq = req.sumReq;
    }

    next();
};

const isAnn = async (req, res, next) => {
    try {
        const oneMonthAgo = new Date();
        oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 3); // Get date 1 month ago

        // Fetch announcements created within the last month
        const announcements = await db.collection("announcements")
            .find({ createdAt: { $gte: oneMonthAgo } }) // Filter by createdAt
            .sort({ createdAt: -1 }) // Sort by updatedAt in descending order
            .toArray();

        // Attach announcements data to the request object
        req.announcements = announcements;

        // Set announcements as a global variable for all views (accessible via res.locals.announcements)
        res.locals.announcements = announcements;

        // Proceed to the next middleware or route handler
        next();
    } catch (err) {
        console.error("Error in isAnn middleware:", err.message);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
    }
};

const myReq = async (req, res, next) => {
  try {
    if (!req.user) {
      console.log("User is not logged in.");
      return res.redirect("/");
    }

    const sessionUserId = req.user._id;
    console.log("🔎 Raw sessionUserId:", sessionUserId);

    // convert to ObjectId if needed
    let objectIdUserId;
    if (typeof sessionUserId === "string" && ObjectId.isValid(sessionUserId)) {
      objectIdUserId = new ObjectId(sessionUserId);
    } else if (sessionUserId instanceof ObjectId) {
      objectIdUserId = sessionUserId;
    } else {
      // fallback - try to coerce
      objectIdUserId = new ObjectId(String(sessionUserId));
    }
    console.log("✅ Converted ObjectId:", objectIdUserId);

    const query = {
      requestBy: objectIdUserId,
      archive: { $in: [0, "0"] }
    };
    console.log("🔍 Running query:", JSON.stringify(query, null, 2));

    const requests = await db.collection("request")
      .find(query)
      .sort({ updatedAt: -1 })
      .toArray();

    console.log(`📌 Requests Found: ${requests.length}`);

    if (requests.length > 0) {
      // Attach documents (robust compare using string)
      const requestIds = requests.map(r => r._id);
      const documents = await db.collection("document")
        .find({ reqId: { $in: requestIds } })
        .toArray();

      requests.forEach(request => {
        request.documents = documents.filter(doc => String(doc.reqId) === String(request._id));
      });

      // helper to test "objectid-ness" for strings/instances
      const isValidOid = (val) => {
        if (!val) return false;
        if (val instanceof ObjectId) return true;
        if (typeof val === "string") return ObjectId.isValid(val);
        try {
          return ObjectId.isValid(String(val));
        } catch (e) {
          return false;
        }
      };

      // collect unique resident ids (as strings) from request.requestFor
      const residentIdSet = new Set();
      requests.forEach(r => {
        const rf = r.requestFor;
        if (!rf || rf === "myself") return;

        if (Array.isArray(rf)) {
          rf.forEach(item => { if (isValidOid(item)) residentIdSet.add(String(item)); });
        } else {
          if (isValidOid(rf)) residentIdSet.add(String(rf));
        }
      });

      if (residentIdSet.size > 0) {
        const residentIds = Array.from(residentIdSet).map(id => new ObjectId(id));
        const residents = await db.collection("resident")
          .find({ _id: { $in: residentIds } })
          .toArray();

        // make a map for fast lookup
        const residentsMap = Object.fromEntries(residents.map(r => [String(r._id), r]));

        // attach residentInfo (handle array or single)
        requests.forEach(request => {
          const rf = request.requestFor;
          if (!rf || rf === "myself") return;

          if (Array.isArray(rf)) {
            const infos = rf.map(item => residentsMap[String(item)]).filter(Boolean);
            if (infos.length) request.residentInfo = infos;
          } else {
            const match = residentsMap[String(rf)];
            if (match) request.residentInfo = match;
          }
        });
      }
    }

    req.requests = requests;
    res.locals.requests = requests;
    next();

  } catch (err) {
    console.error("⚠️ Error in myReq middleware:", err);
    res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
  }
};
const isReq = async (req, res, next) => {
    try {
        // Ensure the user is logged in by checking session
        if (!req.session.userId) {
            return res.redirect("/"); // Redirect if not logged in
        }

        // Fetch requests from the 'request' collection where archive is 0
        const requests = await db.collection("request")
            .find({ archive: { $in: [0, "0"] } })
            .sort({ updatedAt: -1 }) // Sort by updatedAt descending
            .toArray();

        // Fetch corresponding resident, household, and requestFor data for each request
        for (let request of requests) {
            const resident = await db.collection("resident")
                .findOne({ _id: new ObjectId(request.requestBy) }); // always ObjectId
            request.resident = resident;

            if (resident) {
                // Attach household data
                const household = await db.collection("household")
                    .findOne({ _id: new ObjectId(resident.householdId) });
                request.household = household;

                // Fetch requestFor resident (the person the request is for)
                if (request.requestFor) {
                    let requestForId;

                    // Check if already ObjectId or just a string
                    if (ObjectId.isValid(request.requestFor)) {
                        requestForId = new ObjectId(request.requestFor);
                    } else if (typeof request.requestFor === "object" && request.requestFor._id) {
                        requestForId = new ObjectId(request.requestFor._id);
                    }

                    if (requestForId) {
                        const forResident = await db.collection("resident")
                            .findOne({ _id: requestForId });
                        request.requestForData = forResident;
                    }
                }
            }
        }

        // Fetch corresponding documents for each request
        for (let request of requests) {
            const documents = await db.collection("document")
                .find({ reqId: request._id }) // Fetch documents where reqId matches request._id
                .toArray();
            request.documents = documents;
        }

        // Attach the combined data to the request object
        req.requests = requests;

        // Set request as a global variable for all views
        res.locals.requests = requests;

        // Proceed to the next middleware
        next();
    } catch (err) {
        console.error("Error in myReq middleware:", err.message);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
    }
};

const isRsd = async (req, res, next) => {
    try {
        const residents = await db.collection("resident")
            .find({ archive: { $in: [0, "0"] } })
            .sort({ firstName: 1 }) // Sort by firstName in ascending order
            .toArray();

        // Fetch additional household and family data
        const familyIds = residents.map(r => r.familyId).filter(id => id); // Collect valid familyIds
        const householdIds = residents.map(r => r.householdId).filter(id => id); // Collect valid householdIds

        let families = [];
        let households = [];

        if (familyIds.length) {
            families = await db.collection("family")
                .find({ _id: { $in: familyIds.map(id => new ObjectId(id)) } })
                .toArray();
        }

        if (householdIds.length) {
            households = await db.collection("household")
                .find({ _id: { $in: householdIds.map(id => new ObjectId(id)) } })
                .toArray();
        }

        // Map families and households to their respective IDs
        const familyMap = families.reduce((acc, family) => {
            acc[family._id.toString()] = family.poverty || "N/A";
            return acc;
        }, {});

        const householdMap = households.reduce((acc, house) => {
            acc[house._id.toString()] = {
                houseNo: house.houseNo || "N/A",
                purok: house.purok || "N/A"
            };
            return acc;
        }, {});

        // Attach household & family info to each resident
        const residentsWithDetails = residents.map(resident => ({
            ...resident,
            familyPoverty: familyMap[resident.familyId?.toString()] || "N/A",
            houseNo: householdMap[resident.householdId?.toString()]?.houseNo || "N/A",
            purok: householdMap[resident.householdId?.toString()]?.purok || "N/A"
        }));

        // Attach data to request and views
        req.residents = residentsWithDetails;
        res.locals.residents = residentsWithDetails;

        next();
    } catch (err) {
        console.error("Error in isRsd middleware:", err.message);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
    }
};


const isHr = async (req, res, next) => {
    try {
        // Fetch all hearings where archive is 0 or "0", ordered by createdAt
        const hearings = await db.collection("hearing")
            .find({ archive: { $in: [0, "0"] } }) // Filter: Only where archive is 0 or "0"
            .sort({ createdAt: -1 }) // Sort by createdAt in descending order (latest first)
            .toArray();

        // Attach hearings data to the request object
        req.hearings = hearings;

        // Set hearings as a global variable for all views (accessible via res.locals.hearings)
        res.locals.hearings = hearings;

        // Proceed to the next middleware or route handler
        next();
    } catch (err) {
        console.error("Error in isHearing middleware:", err.message);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
    }
};


const getPublicIdFromUrl = (url) => {
  try {
    const parts = url.split("/upload/")[1]; // "v1698765432/uploads/abc123.jpg"
    const withoutVersion = parts.split("/").slice(1).join("/"); // "uploads/abc123.jpg"
    return withoutVersion.replace(/\.[^/.]+$/, ""); // "uploads/abc123"
  } catch (err) {
    console.error("Failed to extract public_id:", err);
    return null;
  }
};

// Routes
app.get("/", (req, res) => res.render("index", { error: "", layout: "layout", title: "Home", activePage: "home" }));
app.get("/passSuccess", (req, res) => res.render("passSuccess", { error: "", layout: "layout", title: "Home", activePage: "home" }));
app.get("/forgot", (req, res) => {
    const error = req.query.error || ""; // Get error or set default empty string
    res.render("forgot", { layout: "forgot", title: "Forgot", activePage: "forgot", error });
});
app.get("/reg", (req, res) => {
    const error = req.query.error || ""; // Get error or set default empty string
    res.render("reg", { layout: "reg", title: "reg", activePage: "reg", error });
});

app.get("/regSuccess", (req, res) => res.render("regSuccess", { layout: "regSuccess", title: "regSuccess", activePage: "regSuccess" }));


app.get("/index2", isRsd, (req, res) => res.render("index2", { layout: "layout", title: "Home", activePage: "home" }));
app.get("/abt", isLogin, (req, res) => res.render("abt", { layout: "layout", title: "About Us", activePage: "abt" }));
app.get("/user", isLogin, (req, res) => res.render("user", { layout: "layout", title: "Profile", activePage: "user" }));
app.get("/prf", isLogin, (req, res) => res.render("prf", { layout: "design", title: "Profile", activePage: "prf" }));
app.get("/arc", isLogin, (req, res) => res.render("arc", { layout: "layout", title: "Archive", activePage: "dsb" }));
app.get("/his", isLogin, (req, res) => res.render("his", { layout: "design", title: "About Us", activePage: "his" }));
app.get("/1", isLogin, (req, res) => res.render("1", { layout: "design", title: "Test", activePage: "1" }));

app.get("/complaintChart", isLogin, (req, res) => res.render("complaintChart", { layout: "layout", title: "Dashboard", activePage: "dsb" }));

app.get("/design", isLogin, myReq, isAnn, (req, res) => res.render("design", { layout: "design", title: "Design", activePage: "design" }));
const RECAPTCHA_SECRET_KEY = "6LcXjtgrAAAAAFM1zexPSsT29OGpHBIo7c_Rbhhf"; 

app.post("/login", async (req, res) => {
    try {
        const { username, password, "g-recaptcha-response": recaptchaToken } = req.body;

        // 🔹 Ensure reCAPTCHA token exists
        if (!recaptchaToken) {
            console.log("No reCAPTCHA token received");
            return res.render("index", { error: "Please complete the reCAPTCHA." });
        }

        // 🔹 Verify reCAPTCHA with Google
        const verifyUrl = "https://www.google.com/recaptcha/api/siteverify";
        const recaptchaResponse = await axios.post(verifyUrl, null, {
            params: { secret: RECAPTCHA_SECRET_KEY, response: recaptchaToken },
        });

        console.log("reCAPTCHA Response:", recaptchaResponse.data);

        if (!recaptchaResponse.data.success) {
            return res.render("index", { error: "reCAPTCHA verification failed. Please try again." });
        }

        // 🔹 Fetch user from the database
        const user = await db.collection("resident").findOne({ username: { $regex: new RegExp(`^${username}$`, "i") } });

        if (!user) {
            console.log("User not found:", username);
            return res.render("index", { error: "Invalid username or password." });
        }

        console.log("User found:", user);

        // 🔹 Check password (direct comparison)
        if (user.password !== password) {
            console.log("Password mismatch for user:", username);
            return res.render("index", { error: "Invalid username or password." });
        }

        // 🔹 Check if suspended
        if (user.suspend === 1 || user.suspend === "1") {
            console.log("Suspended account attempted login:", username);
            return res.render("index", { error: "Account Suspended!" });
        }

        // 🔹 Set session data if login is successful
        req.session.userId = user._id;
        req.session.access = user.access;

        console.log("Session set:", req.session);

        // 🔹 Redirect based on user access
        const redirectPath = user.access === 1 ? "/das" : user.access === 0 ? "/hom" : "/";
        return res.redirect(redirectPath);

    } catch (err) {
        console.error("Login Error:", err.message);
        return res.render("index", { error: "An error occurred. Please try again later."});
    }
});

app.post("/login2", async (req, res) => { 
    try {
        const { username, password, autoLogin } = req.body;

        // 🔹 Fetch user
        const user = await db.collection("resident").findOne({ 
            username: { $regex: new RegExp(`^${username}$`, "i") } 
        });

        if (!user) {
            console.log("User not found:", username);
            return res.send('<script>alert("Invalid username."); window.location="/index2";</script>');
        }

        console.log("User found:", user);

        // 🔹 Skip password check if autoLogin is true
        if (!autoLogin) {
            if (user.password !== password) {
                console.log("Password mismatch for user:", username);
                return res.send('<script>alert("Invalid username or password."); window.location="/index2";</script>');
            }
        }

        // 🔹 Set session
        req.session.userId = user._id;
        req.session.access = user.access;

        console.log("Session set:", req.session);

        // 🔹 Redirect based on access
        const redirectPath = user.access === 1 ? "/das" : user.access === 0 ? "/hom" : "/index2";
        return res.redirect(redirectPath);

    } catch (err) {
        console.error("Login Error:", err.message);
        return res.send('<script>alert("An error occurred. Please try again later."); window.location="/";</script>');
    }
});

app.post("/login20", async (req, res) => {
    try {
        const { username, password } = req.body;

        // 🔹 Fetch user from the database
        const user = await db.collection("resident").findOne({ username: { $regex: new RegExp(`^${username}$`, "i") } });

        if (!user) {
            console.log("User not found:", username);
            return res.send('<script>alert("Invalid username or password."); window.location="/index2";</script>');
        }

        console.log("User found:", user);

        // 🔹 Check password (direct comparison)
        if (user.password !== password) {
            console.log("Password mismatch for user:", username);
            return res.send('<script>alert("Invalid username or password."); window.location="/index2";</script>');
        }

        // 🔹 Set session data if login is successful
        req.session.userId = user._id;
        req.session.access = user.access;

        console.log("Session set:", req.session);

        // 🔹 Redirect based on user access
        const redirectPath = user.access === 1 ? "/das" : user.access === 0 ? "/hom" : "/index2";
        return res.redirect(redirectPath);

    } catch (err) {
        console.error("Login Error:", err.message);
        return res.send('<script>alert("An error occurred. Please try again later."); window.location="/";</script>');
    }
});

app.get("/rst/:id", async (req, res) => {
    try {
        const userId = req.params.id;

        // Find the user by ID
        const user = await db.collection("resident").findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.send('<script>alert("User not found."); window.location="/";</script>');
        }

        // Render the password reset page with current password + id
        res.render("rst", { 
            userId: userId,
            currentPassword: user.password
        });

    } catch (error) {
        console.error("Error loading reset page:", error);
        res.send('<script>alert("An error occurred. Please try again later."); window.location="/";</script>');
    }
});


// Logout Route
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout Error:", err.message);
            return res.status(500).json({ error: "Logout failed" });
        }
        res.redirect("/");
    });
});

app.get("/ann", isLogin, async (req, res) => {
  try {
    const announcements = await db.collection("announcements").aggregate([
      // Convert postBy to ObjectId if it’s a string
      {
        $addFields: {
          postByObj: {
            $cond: [
              { $eq: [{ $type: "$postBy" }, "string"] }, // if type is string
              { $toObjectId: "$postBy" },                // convert to ObjectId
              "$postBy"                                  // else keep as is
            ]
          }
        }
      },
      // Lookup resident details
      {
        $lookup: {
          from: "resident",
          localField: "postByObj",
          foreignField: "_id",
          as: "residentDetails"
        }
      },
      // Flatten result but keep announcements even without resident
      {
        $unwind: {
          path: "$residentDetails",
          preserveNullAndEmptyArrays: true
        }
      },
      // Sort by newest
      { $sort: { createdAt: -1 } }
    ]).toArray();

    res.render("ann", {
      layout: "layout",
      title: "Announcements",
      activePage: "ann",
      announcements
    });
  } catch (err) {
    console.error("❌ Error fetching announcements:", err.message);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/newAnn", upload.single("image"), async (req, res) => {
    try {
        const { title, description, postBy } = req.body;
        const imagePath = req.file ? path.join("/uploads", req.file.filename) : null;

        if (!title || !description) {
            return res.send('<script>alert("Title and Description are required!"); window.location="/ann";</script>');
        }

        const newAnnouncement = {
            title,
            description,
            postBy,
            image: imagePath,
            createdAt: new Date(),
        };

        await db.collection("announcements").insertOne(newAnnouncement);

        // Fetch all resident emails
        const residents = await db.collection("resident").find({ email: { $exists: true, $ne: null } }).toArray();

        // Send emails using Nodemailer
        const emailPromises = residents.map(resident => {
            const mailOptions = {
                from: 'johnniebre1995@gmail.com',
                to: resident.email,
                subject: `New Announcement: ${title}`,
                text: `Dear Resident,\n\nWe have a new announcement:\n\nTitle: ${title}\nDescription: ${description}\n\nThank you.`,
                html: `
                    <p>Dear Resident,</p>
                    <p>We have a new announcement:</p>
                    <p><strong>Title:</strong> ${title}</p>
                    <p><strong>Description:</strong> ${description}</p>
                    <p>Thank you.</p>
                `
            };

            return transporter.sendMail(mailOptions)
                .then(() => {
                    console.log(`Email successfully sent to ${resident.email}`);
                })
                .catch((error) => {
                    console.error(`Failed to send email to ${resident.email}:`, error.message);
                });
        });

        await Promise.all(emailPromises);

        res.send('<script>alert("Announcement added successfully and sent to all residents!"); window.location="/ann";</script>');

    } catch (err) {
        console.error("Error adding announcement:", err.stack);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/ann";</script>');
    }
});

app.post("/editAnn/:id", isLogin, upload.single("image"), async (req, res) => {
    try {
        const { id } = req.params; // Get the ID from the URL parameter
        const { title, description } = req.body; // Get the form fields (title and description)
        const image = req.file; // Get the uploaded image file (if any)

        // Validate the ID
        if (!ObjectId.isValid(id)) {
            return res.status(400).send('<script>alert("Invalid announcement ID!"); window.location="/ann";</script>');
        }

        const objectId = new ObjectId(id); // Convert the ID to an ObjectId

        // Fetch the existing announcement from the database
        const existingAnnouncement = await db.collection("announcements").findOne({ _id: objectId });

        if (!existingAnnouncement) {
            return res.status(404).send('<script>alert("Announcement not found!"); window.location="/ann";</script>');
        }

        // Prepare the update data object
        const updateData = {
            title: title || existingAnnouncement.title, // Use existing title if new title is not provided
            description: description || existingAnnouncement.description, // Use existing description if new description is not provided
            updatedAt: new Date() // Always update the timestamp
        };

        // If there's an image, handle it
if (image) {
    const imageUrl = image.path; 
    updateData.image = imageUrl; 

    if (existingAnnouncement.image) {
        const publicId = getPublicIdFromUrl(existingAnnouncement.image);
        if (publicId) {
            cloudinary.uploader.destroy(publicId, (err, result) => {
                if (err) console.error("Error deleting old image from Cloudinary:", err);
                else console.log("Old image deleted:", result);
            });
        }
    }
} else {
    updateData.image = existingAnnouncement.image;
}

        // Update the announcement in the database
        const result = await db.collection("announcements").updateOne(
            { _id: objectId }, // Find the announcement by ID
            { $set: updateData } // Update the fields with new data
        );

        // Check if the update was successful
        if (result.modifiedCount > 0) {
            return res.send('<script>alert("Announcement updated successfully!"); window.location="/ann";</script>');
        } else {
            return res.send('<script>alert("No changes were made!"); window.location="/ann";</script>');
        }
    } catch (err) {
        console.error("Error updating announcement:", err);
        res.status(500).send('<script>alert("Error updating the announcement. Please try again."); window.location="/ann";</script>');
    }
});

// Delete an announcement
app.post("/deleteAnn/:id", async (req, res) => {
    try {
        // Delete the announcement from the database using ObjectId
        await db.collection("announcements").deleteOne({ _id: new ObjectId(req.params.id) });
        
        // Redirect to the announcements page after deletion
        res.redirect("/ann");
    } catch (err) {
        console.error("❌ Error deleting announcement:", err.message);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/ann";</script>');
    }
});

app.post("/add-resident", async (req, res) => {
    try {
        const { 
            firstName, middleName, lastName, extName, position, houseNo, purok, role, 
            priority, priorityType, bDay, bMonth, bYear, birthPlace, gender, 
            civilStatus, precinct, phone, email, headId, soloParent, pwd, indigent 
        } = req.body;

        if (!firstName || !lastName || !houseNo || !purok || !role) {
            return res.send('<script>alert("Please fill out all required fields!"); window.location="/rsd";</script>');
        }

        const birthDate = new Date(`${bYear}-${bMonth}-${bDay}`);
        const today = new Date();
        let age = today.getFullYear() - birthDate.getFullYear();
        const monthDiff = today.getMonth() - birthDate.getMonth();
        if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
            age--;
        }

        let username = null;
        let password = null;
        let shouldSendEmail = true;

        const officialPositions = [
            "Punong Barangay", "Barangay Kagawad", "Barangay Secretary", 
            "Barangay Treasurer", "Barangay BHW", "Barangay BIC", 
            "Barangay BNS", "Barangay BPO", "Barangay Clerk", "Barangay Worker"
        ];

        const access = officialPositions.includes(position) ? 1 : 0;

        if (age > 15) {
            const generateRandomPassword = () => {
                const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
                let password = "";
                for (let i = 0; i < 12; i++) {
                    password += chars.charAt(Math.floor(Math.random() * chars.length));
                }
                return password;
            };

            password = generateRandomPassword();

            const generateUsername = (firstName, middleName, lastName, bDay, bYear) => {
                const firstPart = firstName.charAt(0).toLowerCase() + firstName.slice(-1).toLowerCase();
                let middlePart = "";
                if (middleName) {
                    middlePart = middleName.charAt(0).toLowerCase() + middleName.slice(-1).toLowerCase();
                } else {
                    middlePart = lastName.charAt(0).toLowerCase() + lastName.slice(-1).toLowerCase();
                }
                const lastNameLower = lastName.toLowerCase();
                return `${firstPart}${middlePart}.${lastNameLower}${bDay.padStart(2, '0')}${bYear.slice(-2)}`;
            };

            username = generateUsername(firstName, middleName, lastName, bDay, bYear);
        } else {
            shouldSendEmail = false;
        }

        const isChecked = (value) => (value ? "YES" : "");
        let finalIndigent = isChecked(indigent);

        if (role === "Member" && headId) {
            const headResident = await db.collection("resident").findOne({ _id: new ObjectId(headId) });
            if (headResident && headResident.indigent === "YES") {
                finalIndigent = "YES";
            }
        }

        const newResident = {
            firstName, middleName, lastName, extName, position, houseNo, purok, role,
            priority, priorityType, bDay, bMonth, bYear, birthPlace, gender, 
            civilStatus, precinct, phone, email, username, password,
            access,
            archive: 0, headId,
            soloParent: isChecked(soloParent),
            pwd: isChecked(pwd),
            indigent: finalIndigent,
            createdAt: new Date(),
            updatedAt: null
        };

        await db.collection("resident").insertOne(newResident);

        if (shouldSendEmail) {
            let recipientEmail = email;

            if (!email && headId) {
                const headResident = await db.collection("resident").findOne({ _id: new ObjectId(headId) });
                if (headResident && headResident.email) {
                    recipientEmail = headResident.email;
                }
            }

            if (recipientEmail) {
                const mailOptions = {
                    from: 'johnniebre1995@gmail.com',
                    to: recipientEmail,
                    subject: "Your Resident Account Details",
                    text: `Dear ${firstName},\n\nYour resident account has been created.\nUsername: ${username}\nPassword: ${password}\n\nPlease keep your credentials secure.\n\nThank you.`,
                    html: `<p>Dear <strong>${firstName}</strong>,</p>
                           <p>Your resident account has been created.</p>
                           <p><strong>Username:</strong> ${username}</p>
                           <p><strong>Password:</strong> ${password}</p>
                           <p>Please keep your credentials secure.</p>
                           <p>Thank you.</p>`,
                };

                await transporter.sendMail(mailOptions);
                console.log(`Email sent to ${recipientEmail}`);
            }
        }

        res.send('<script>alert("Resident added successfully!"); window.location="/rsd";</script>');

    } catch (err) {
        console.error("Error adding resident:", err.message);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/rsd";</script>');
    }
});


app.get("/arcRsd", isLogin, async (req, res) => {
    try {
        const residents = await db.collection("resident")
            .find({ archive: { $in: [1, "1"] } })
            .sort({ firstName: 1 })
            .toArray();

        const households = await db.collection("household")
            .find({ archive: { $in: [0, "0"] } })
            .toArray();

        const families = await db.collection("family")
            .find({ archive: { $in: [0, "0"] } })
            .toArray();

        // Map household and family data
        const householdMap = new Map();
        households.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Process residents
        residents.forEach(resident => {
            // Get household details
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo = householdData.houseNo;
            resident.purok = householdData.purok;

            // Get family details
            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        }); 

        // Get total counts from actual collections
        const totalHouseholds = households.length;
        const totalFamilies = families.length;
        const totalInhabitants = residents.length;
        const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length;

        res.render("rsdArc", {
            layout: "layout",
            title: "Archive",
            activePage: "rsd",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            titlePage : "Records of INHABITANTS",
            moment
        });
    } catch (err) {
        console.error("❌ Error fetching residents:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});


app.get("/res", isLogin, async (req, res) => {
    try {
        const residents = await db.collection("resident")
            .find({ archive: { $in: [0, "0"] } })
            .sort({ firstName: 1 })
            .toArray();

        const households = await db.collection("household")
            .find({ archive: { $in: [0, "0"] } })
            .toArray();

        const families = await db.collection("family")
            .find({ archive: { $in: [0, "0"] } })
            .toArray();

        // Map household and family data
        const householdMap = new Map();
        households.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Process residents
        residents.forEach(resident => {
            // Get household details
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo2 = householdData.houseNo;
            resident.purok2 = householdData.purok;

            // Get family details
            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        }); 

        // Get total counts from actual collections
        const totalHouseholds = households.length;
        const totalFamilies = families.length;
        const totalInhabitants = residents.length;
        const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length;

        res.render("res", {
            layout: "layout",
            title: "Residents",
            activePage: "res",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            titlePage : "Records of INHABITANTS",
            moment
        });
    } catch (err) {
        console.error("❌ Error fetching residents:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});


app.get("/ver", isLogin, async (req, res) => {
    try {
        const residents = await db.collection("resident")
            .find({ archive: { $in: [1, "1"] },
            verify: { $in: [1, "1"] } })
            .sort({ firstName: 1 })
            .toArray();

        const households = await db.collection("household")
            .find({ archive: { $in: [0, "0"] } })
            .toArray();

        const families = await db.collection("family")
            .find({ archive: { $in: [0, "0"] } })
            .toArray();

        // Map household and family data
        const householdMap = new Map();
        households.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Process residents
        residents.forEach(resident => {
            // Get household details
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo2 = householdData.houseNo;
            resident.purok2 = householdData.purok;

            // Get family details
            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        }); 

        // Get total counts from actual collections
        const totalHouseholds = households.length;
        const totalFamilies = families.length;
        const totalInhabitants = residents.length;
        const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length;

        res.render("ver", {
            layout: "layout",
            title: "Residents",
            activePage: "ver",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            titlePage : "Records of INHABITANTS",
            moment
        });
    } catch (err) {
        console.error("❌ Error fetching residents:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});



app.get("/archiv", isLogin, async (req, res) => {
    try {
        const residents = await db.collection("resident")
            .find({ archive: { $in: [1, "1"] } })
            .sort({ firstName: 1 })
            .toArray();

        const households = await db.collection("household")
            .find({ archive: { $in: [0, "0"] } })
            .toArray();

        const families = await db.collection("family")
            .find({ archive: { $in: [0, "0"] } })
            .toArray();

        // Map household and family data
        const householdMap = new Map();
        households.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Process residents
        residents.forEach(resident => {
            // Get household details
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo2 = householdData.houseNo;
            resident.purok2 = householdData.purok;

            // Get family details
            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        }); 

        // Get total counts from actual collections
        const totalHouseholds = households.length;
        const totalFamilies = families.length;
        const totalInhabitants = residents.length;
        const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length;

        res.render("archiv", {
            layout: "layout",
            title: "Residents",
            activePage: "res",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            titlePage : "Records of INHABITANTS",
            moment
        });
    } catch (err) {
        console.error("❌ Error fetching residents:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});

app.get("/prior", isLogin, async (req, res) => {
  try {
    const residentRaw = await db.collection("resident")
  .find({ archive: { $in: [0, "0"] } }) // no $or here!
  .sort({ firstName: 1 })
  .toArray();

    const households = await db.collection("household")
      .find({ archive: { $in: [0, "0"] } })
      .toArray();

    const families = await db.collection("family")
      .find({ archive: { $in: [0, "0"] } })
      .toArray();

    // Function to calculate age from birthdate (Handles Month Names)
    function calculateAge(bMonth, bDay, bYear) {
      if (!bMonth || !bDay || !bYear) return 0;

      // Convert month name to number if needed
      const monthNumber = isNaN(bMonth) ? moment().month(bMonth).format("M") : bMonth;
      return moment().diff(`${bYear}-${monthNumber}-${bDay}`, 'years');
    }

    // ✅ Add senior citizens (>= 60) to the filtered set
    const residents = residentRaw.filter(r =>
      calculateAge(r.bMonth, r.bDay, r.bYear) >= 60 ||
      r.pregnant === "on" || r.pregnant === "Yes" ||
      r.pwd === "on" || r.pwd === "Yes" ||
      r.soloParent === "on" || r.soloParent === "Yes"
    );

    // Map household and family data
    const householdMap = new Map();
    households.forEach(household => {
      householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
    });

    const familyMap = new Map();
    families.forEach(family => {
      familyMap.set(String(family._id), { poverty: family.poverty });
    });

    // Process residents
    residents.forEach(resident => {
      const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
      resident.houseNo = householdData.houseNo;
      resident.purok = householdData.purok;

      const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
      resident.familyPoverty = familyData.poverty;
    });

    // Get total counts
    const totalHouseholds = households.length;
    const totalFamilies = families.length;
    const totalInhabitants = residents.length;
    const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length;

    res.render("prior", {
      layout: "layout",
      title: "Residents",
      activePage: "rsd",
      residents,
      totalHouseholds,
      totalFamilies,
      totalInhabitants,
      totalVoters,
      titlePage: "Priority Groups List",
      moment
    });
  } catch (err) {
    console.error("❌ Error fetching residents:", err);
    res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
  }
});

app.get("/rsdD", isLogin, async (req, res) => {
    try {
        // --- STEP 1: Filter Households for "Dike" Purok ---
        const dikeHouseholds = await db.collection("household")
            .find({ archive: { $in: [0, "0"] }, purok: "Dike" }) // Filter for active households in "Dike"
            .toArray();

        // Extract IDs of "Dike" households
        const dikeHouseholdIds = dikeHouseholds.map(h => h._id.toString());

        // --- STEP 2: Filter Residents using "Dike" household IDs ---
        const residents = await db.collection("resident")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .sort({ firstName: 1 })
            .toArray();

        // --- STEP 3: Filter Families using "Dike" household IDs ---
        const families = await db.collection("family")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .toArray();

        // Map household data (only for Dike households now)
        const householdMap = new Map();
        dikeHouseholds.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        // Map family data (only for families in Dike households now)
        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Process residents
        residents.forEach(resident => {
            // Get household details from the Dike households map
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo = householdData.houseNo;
            resident.purok = householdData.purok;

            // Get family details from the Dike families map
            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        });

        // Get total counts from the filtered data
        const totalHouseholds = dikeHouseholds.length; // Count of Dike households
        const totalFamilies = families.length; // Count of families in Dike households
        const totalInhabitants = residents.length; // Count of residents in Dike households
        const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length; // Voters in Dike households

        res.render("rsd", {
            layout: "layout",
            title: "Residents (Dike Purok)", // Updated title
            activePage: "rsd",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            titlePage : "Residents from Purok Dike"
        });
    } catch (err) {
        console.error("❌ Error fetching Dike residents:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});

app.get("/rsdC", isLogin, async (req, res) => {
    try {
        // --- STEP 1: Filter Households for "Dike" Purok ---
        const dikeHouseholds = await db.collection("household")
            .find({ archive: { $in: [0, "0"] }, purok: "Cantarilla" }) // Filter for active households in "Dike"
            .toArray();

        // Extract IDs of "Dike" households
        const dikeHouseholdIds = dikeHouseholds.map(h => h._id.toString());

        // --- STEP 2: Filter Residents using "Dike" household IDs ---
        const residents = await db.collection("resident")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .sort({ firstName: 1 })
            .toArray();

        // --- STEP 3: Filter Families using "Dike" household IDs ---
        const families = await db.collection("family")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .toArray();

        // Map household data (only for Dike households now)
        const householdMap = new Map();
        dikeHouseholds.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        // Map family data (only for families in Dike households now)
        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Process residents
        residents.forEach(resident => {
            // Get household details from the Dike households map
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo = householdData.houseNo;
            resident.purok = householdData.purok;

            // Get family details from the Dike families map
            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        });

        // Get total counts from the filtered data
        const totalHouseholds = dikeHouseholds.length; // Count of Dike households
        const totalFamilies = families.length; // Count of families in Dike households
        const totalInhabitants = residents.length; // Count of residents in Dike households
        const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length; // Voters in Dike households

        res.render("rsd", {
            layout: "layout",
            title: "Cantarilla", // Updated title
            activePage: "rsd",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            titlePage : "Residents from Purok Cantarilla"
        });
    } catch (err) {
        console.error("❌ Error fetching Dike residents:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});

app.get("/rsdP", isLogin, async (req, res) => {
    try {
        // --- STEP 1: Filter Households for "Dike" Purok ---
        const dikeHouseholds = await db.collection("household")
            .find({ archive: { $in: [0, "0"] }, purok: "Perigola" }) // Filter for active households in "Dike"
            .toArray();

        // Extract IDs of "Dike" households
        const dikeHouseholdIds = dikeHouseholds.map(h => h._id.toString());

        // --- STEP 2: Filter Residents using "Dike" household IDs ---
        const residents = await db.collection("resident")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .sort({ firstName: 1 })
            .toArray();

        // --- STEP 3: Filter Families using "Dike" household IDs ---
        const families = await db.collection("family")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .toArray();

        // Map household data (only for Dike households now)
        const householdMap = new Map();
        dikeHouseholds.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        // Map family data (only for families in Dike households now)
        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Process residents
        residents.forEach(resident => {
            // Get household details from the Dike households map
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo = householdData.houseNo;
            resident.purok = householdData.purok;

            // Get family details from the Dike families map
            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        });

        // Get total counts from the filtered data
        const totalHouseholds = dikeHouseholds.length; // Count of Dike households
        const totalFamilies = families.length; // Count of families in Dike households
        const totalInhabitants = residents.length; // Count of residents in Dike households
        const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length; // Voters in Dike households

        res.render("rsd", {
            layout: "layout",
            title: "Perigola", // Updated title
            activePage: "rsd",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            titlePage : "Residents from Purok Perigola"
        });
    } catch (err) {
        console.error("❌ Error fetching Dike residents:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});

app.get("/rsdB", isLogin, async (req, res) => {
    try {
        // --- STEP 1: Filter Households for "Dike" Purok ---
        const dikeHouseholds = await db.collection("household")
            .find({ archive: { $in: [0, "0"] }, purok: "Bagong Daan" }) // Filter for active households in "Dike"
            .toArray();

        // Extract IDs of "Dike" households
        const dikeHouseholdIds = dikeHouseholds.map(h => h._id.toString());

        // --- STEP 2: Filter Residents using "Dike" household IDs ---
        const residents = await db.collection("resident")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .sort({ firstName: 1 })
            .toArray();

        // --- STEP 3: Filter Families using "Dike" household IDs ---
        const families = await db.collection("family")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .toArray();

        // Map household data (only for Dike households now)
        const householdMap = new Map();
        dikeHouseholds.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        // Map family data (only for families in Dike households now)
        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Process residents
        residents.forEach(resident => {
            // Get household details from the Dike households map
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo = householdData.houseNo;
            resident.purok = householdData.purok;

            // Get family details from the Dike families map
            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        });

        // Get total counts from the filtered data
        const totalHouseholds = dikeHouseholds.length; // Count of Dike households
        const totalFamilies = families.length; // Count of families in Dike households
        const totalInhabitants = residents.length; // Count of residents in Dike households
        const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length; // Voters in Dike households

        res.render("rsd", {
            layout: "layout",
            title: "Bagong Daan", // Updated title
            activePage: "rsd",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            titlePage : "Residents from Purok Bagong Daan"
        });
    } catch (err) {
        console.error("❌ Error fetching Dike residents:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});

app.get("/rsdS", isLogin, async (req, res) => {
    try {
        // --- STEP 1: Filter Households for "Dike" Purok ---
        const dikeHouseholds = await db.collection("household")
            .find({ archive: { $in: [0, "0"] }, purok: "Shortcut" }) // Filter for active households in "Dike"
            .toArray();

        // Extract IDs of "Dike" households
        const dikeHouseholdIds = dikeHouseholds.map(h => h._id.toString());

        // --- STEP 2: Filter Residents using "Dike" household IDs ---
        const residents = await db.collection("resident")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .sort({ firstName: 1 })
            .toArray();

        // --- STEP 3: Filter Families using "Dike" household IDs ---
        const families = await db.collection("family")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .toArray();

        // Map household data (only for Dike households now)
        const householdMap = new Map();
        dikeHouseholds.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        // Map family data (only for families in Dike households now)
        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Process residents
        residents.forEach(resident => {
            // Get household details from the Dike households map
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo = householdData.houseNo;
            resident.purok = householdData.purok;

            // Get family details from the Dike families map
            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        });

        // Get total counts from the filtered data
        const totalHouseholds = dikeHouseholds.length; // Count of Dike households
        const totalFamilies = families.length; // Count of families in Dike households
        const totalInhabitants = residents.length; // Count of residents in Dike households
        const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length; // Voters in Dike households

        res.render("rsd", {
            layout: "layout",
            title: "Shortcut", // Updated title
            activePage: "rsd",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            titlePage : "Residents from Purok Shortcut"
        });
    } catch (err) {
        console.error("❌ Error fetching Dike residents:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});

app.get("/rsdH", isLogin, async (req, res) => {
    try {
        // --- STEP 1: Filter Households for "Dike" Purok ---
        const dikeHouseholds = await db.collection("household")
            .find({ archive: { $in: [0, "0"] }, purok: "Maharlika Highway" }) // Filter for active households in "Dike"
            .toArray();

        // Extract IDs of "Dike" households
        const dikeHouseholdIds = dikeHouseholds.map(h => h._id.toString());

        // --- STEP 2: Filter Residents using "Dike" household IDs ---
        const residents = await db.collection("resident")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .sort({ firstName: 1 })
            .toArray();

        // --- STEP 3: Filter Families using "Dike" household IDs ---
        const families = await db.collection("family")
            .find({
                archive: { $in: [0, "0"] },
                householdId: { $in: dikeHouseholdIds.map(id => new ObjectId(id)) } // Ensure ObjectIds for query
            })
            .toArray();

        // Map household data (only for Dike households now)
        const householdMap = new Map();
        dikeHouseholds.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        // Map family data (only for families in Dike households now)
        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Process residents
        residents.forEach(resident => {
            // Get household details from the Dike households map
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo = householdData.houseNo;
            resident.purok = householdData.purok;

            // Get family details from the Dike families map
            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        });

        // Get total counts from the filtered data
        const totalHouseholds = dikeHouseholds.length; // Count of Dike households
        const totalFamilies = families.length; // Count of families in Dike households
        const totalInhabitants = residents.length; // Count of residents in Dike households
        const totalVoters = residents.filter(resident => resident.precinct === "Registered Voter").length; // Voters in Dike households

        res.render("rsd", {
            layout: "layout",
            title: " Maharlika Highway", // Updated title
            activePage: "rsd",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            titlePage : "Residents from Purok Maharlika Highway"
        });
    } catch (err) {
        console.error("❌ Error fetching Dike residents:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});


app.post("/reset-resident/:id", async (req, res) => {
  if (!db) {
    return res.status(500).json({ success: false, message: "Database not connected" });
  }

  const residentId = req.params.id;

  function generateRandomPassword() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    let password = "";
    for (let i = 0; i < 12; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
  }

  const newPassword = generateRandomPassword();

  try {
    const resident = await db.collection("resident").findOne({ _id: new ObjectId(residentId) });
    if (!resident) {
      return res.status(404).json({ success: false, message: "Resident not found" });
    }

    const result = await db.collection("resident").updateOne(
      { _id: new ObjectId(residentId) },
      { $set: { password: newPassword } }
    );

    if (result.modifiedCount === 1) {
      // ✅ Respond success immediately
      res.json({ success: true, newPassword });

      // 📧 Handle email sending in the background
      let emailToSend = resident.email;
      if (!emailToSend && resident.headId) {
        const familyHead = await db.collection("resident").findOne({ _id: new ObjectId(resident.headId) });
        emailToSend = familyHead ? familyHead.email : null;
      }

      if (emailToSend) {
        const mailOptions = {
          from: '"Barangay San Andres" <johnniebre1995@gmail.com>',
          to: emailToSend,
          subject: 'Password Reset',
          text: `Your new password is: ${newPassword}`,
          html: `<strong>Your new password is: ${newPassword}</strong>`,
        };

        transporter.sendMail(mailOptions).catch((emailError) => {
          console.error("Error sending email:", emailError);
        });
      } else {
        console.warn("No email found for resident or family head, skipping email send.");
      }
    } else {
      res.status(404).json({ success: false, message: "Resident not found or password not updated" });
    }
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.post("/suspend-resident/:id", async (req, res) => {
    if (!db) return res.status(500).json({ success: false, message: "Database not connected" });

    const residentId = req.params.id.trim();

    if (!ObjectId.isValid(residentId)) {
        return res.status(400).json({ success: false, message: "Invalid resident ID" });
    }

    try {
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(residentId) });

        if (!resident) {
            return res.status(404).json({ success: false, message: "Resident not found" });
        }

        const result = await db.collection("resident").updateOne(
            { _id: new ObjectId(residentId) },
            { $set: { suspend: 1 } }
        );

        if (result.modifiedCount === 1) {
            // ✅ Respond success immediately
            res.json({ success: true, message: "Resident suspended successfully." });

            // 📧 Send email in the background
            if (resident.email) {
                const mailOptions = {
                    from: "johnniebre1995@gmail.com",
                    to: resident.email,
                    subject: "Account Suspension Notification",
                    text: `Dear ${resident.firstName},\n\nWe regret to inform you that your account has been suspended.\n\nThank you.`,
                    html: `<p>Dear <strong>${resident.firstName}</strong>,</p>
                           <p>We regret to inform you that your account has been <strong>suspended</strong>.</p>
                           <p>If you believe this was an error, please contact your barangay office.</p>
                           <p>Thank you.</p>`,
                };

                transporter.sendMail(mailOptions)
                    .then(() => console.log("Suspension email sent to:", resident.email))
                    .catch((emailError) => console.error("Failed to send suspension email:", emailError.message));
            }
        } else {
            res.status(404).json({ success: false, message: "Resident not found." });
        }
    } catch (error) {
        console.error("Error suspending resident:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});


app.post("/decline-reg/:id", async (req, res) => {
    if (!db) return res.status(500).json({ success: false, message: "Database not connected" });

    const residentId = req.params.id.trim();

    if (!ObjectId.isValid(residentId)) {
        return res.status(400).json({ success: false, message: "Invalid resident ID" });
    }

    try {
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(residentId) });

        if (!resident) {
            return res.status(404).json({ success: false, message: "Resident not found" });
        }

        const result = await db.collection("resident").updateOne(
            { _id: new ObjectId(residentId) },
            { $set: { suspend: 1, archive: 1, verify: 3 } }
        );

        if (result.modifiedCount === 1) {
            // ✅ Respond success immediately
            res.json({ success: true, message: "Resident suspended successfully." });

            // 📧 Send email in the background
            if (resident.email) {
                const mailOptions = {
                    from: "johnniebre1995@gmail.com",
                    to: resident.email,
                    subject: "Registration Declined",
                    text: `Dear ${resident.firstName},\n\nWe regret to inform you that your registration has been decline.\n\nThank you.`,
                    html: `<p>Dear <strong>${resident.firstName}</strong>,</p>
                           <p>We regret to inform you that your registration has been <strong>decline</strong>.</p>
                           <p>If you believe this was an error, please contact your barangay office.</p>
                           <p>Thank you.</p>`,
                };

                transporter.sendMail(mailOptions)
                    .then(() => console.log("Suspension email sent to:", resident.email))
                    .catch((emailError) => console.error("Failed to send suspension email:", emailError.message));
            }
        } else {
            res.status(404).json({ success: false, message: "Resident not found." });
        }
    } catch (error) {
        console.error("Error suspending resident:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});
app.post("/approve-reg/:id", async (req, res) => {
    if (!db) return res.status(500).json({ success: false, message: "Database not connected" });

    const residentId = req.params.id.trim();

    if (!ObjectId.isValid(residentId)) {
        return res.status(400).json({ success: false, message: "Invalid resident ID" });
    }

    try {
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(residentId) });

        if (!resident) {
            return res.status(404).json({ success: false, message: "Resident not found" });
        }

        const result = await db.collection("resident").updateOne(
            { _id: new ObjectId(residentId) },
            { $set: { suspend: 0, archive: 0, verify: 0 } }
        );

        if (result.modifiedCount === 1) {
            // ✅ Respond success immediately
            res.json({ success: true, message: "Registration approved successfully." });

            // 📧 Send approval email in the background
            if (resident.email) {
                const mailOptions = {
                    from: "johnniebre1995@gmail.com",
                    to: resident.email,
                    subject: "Registration Approved",
                    text: `Dear ${resident.firstName},\n\nYour registration has been approved.\n\nHere are your login details:\nUsername: ${resident.username}\nPassword: ${resident.password}\n\nYou may now access barangay services using your account.\n\nThank you.`,
                    html: `<p>Dear <strong>${resident.firstName}</strong>,</p>
                           <p>Your registration has been <strong>approved</strong>.</p>
                           <p>Here are your login details:</p>
                           <p><strong>Username:</strong> ${resident.username}</p>
                           <p><strong>Password:</strong> ${resident.password}</p>
                           <p>You may now access barangay services using your account.</p>
                           <p>Thank you.</p>`
                };

                transporter.sendMail(mailOptions)
                    .then(() => console.log("Approval email sent to:", resident.email))
                    .catch((emailError) => console.error("Failed to send approval email:", emailError.message));
            }
        } else {
            res.status(404).json({ success: false, message: "Resident not found." });
        }
    } catch (error) {
        console.error("Error approving resident:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});


app.post("/suspend2-resident/:id", async (req, res) => {
    if (!db) return res.status(500).json({ success: false, message: "Database not connected" });

    const residentId = req.params.id.trim();

    if (!ObjectId.isValid(residentId)) {
        return res.status(400).json({ success: false, message: "Invalid resident ID" });
    }

    try {
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(residentId) });

        if (!resident) {
            return res.status(404).json({ success: false, message: "Resident not found" });
        }

        const result = await db.collection("resident").updateOne(
            { _id: new ObjectId(residentId) },
            { $set: { suspend: 0 } }
        );

        if (result.modifiedCount === 1) {
            // ✅ Respond success immediately
            res.json({ success: true, message: "Resident suspended successfully." });

            // 📧 Send email in the background
            if (resident.email) {
                const mailOptions = {
                    from: "johnniebre1995@gmail.com",
                    to: resident.email,
                    subject: "Account Unsuspension Notification",
                    text: `Dear ${resident.firstName},\n\nWe are happy to inform you that your account has been unsuspended.\n\nThank you.`,
                    html: `<p>Dear <strong>${resident.firstName}</strong>,</p>
                           <p>We are happy to inform you that your account has been <strong>unsuspended</strong>.</p>`,
                };

                transporter.sendMail(mailOptions)
                    .then(() => console.log("Suspension email sent to:", resident.email))
                    .catch((emailError) => console.error("Failed to send suspension email:", emailError.message));
            }
        } else {
            res.status(404).json({ success: false, message: "Resident not found." });
        }
    } catch (error) {
        console.error("Error suspending resident:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});
app.post("/archive-resident/:id", async (req, res) => {
    if (!db) return res.status(500).json({ success: false, message: "Database not connected" });

    const residentId = req.params.id.trim();

    if (!ObjectId.isValid(residentId)) {
        return res.status(400).json({ success: false, message: "Invalid resident ID" });
    }

    try {
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(residentId) });

        if (!resident) {
            return res.status(404).json({ success: false, message: "Resident not found" });
        }

        const result = await db.collection("resident").updateOne(
            { _id: new ObjectId(residentId) },
            { $set: { archive: 1, suspend: 1 } }   // ✅ archive + suspend
        );

        if (result.modifiedCount === 1) {
            // ✅ Respond success immediately
            res.json({ success: true, message: "Resident archived & suspended successfully." });

            // 📧 Send email in the background
            if (resident.email) {
                const mailOptions = {
                    from: "johnniebre1995@gmail.com",
                    to: resident.email,
                    subject: "Account Archived & Suspended",
                    text: `Dear ${resident.firstName},\n\nWe regret to inform you that your account has been archived and suspended.\n\nThank you.`,
                    html: `<p>Dear <strong>${resident.firstName}</strong>,</p>
                           <p>We regret to inform you that your account has been <strong>archived and suspended</strong>.</p>
                           <p>If you believe this was an error, please contact your barangay office.</p>
                           <p>Thank you.</p>`,
                };

                transporter.sendMail(mailOptions)
                    .then(() => console.log("Archive + Suspension email sent to:", resident.email))
                    .catch((emailError) => console.error("Failed to send email:", emailError.message));
            }
        } else {
            res.status(404).json({ success: false, message: "Resident not found." });
        }
    } catch (error) {
        console.error("Error archiving resident:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});
app.post("/archive2-resident/:id", async (req, res) => {
    if (!db) return res.status(500).json({ success: false, message: "Database not connected" });

    const residentId = req.params.id.trim();

    if (!ObjectId.isValid(residentId)) {
        return res.status(400).json({ success: false, message: "Invalid resident ID" });
    }

    try {
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(residentId) });

        if (!resident) {
            return res.status(404).json({ success: false, message: "Resident not found" });
        }

        const result = await db.collection("resident").updateOne(
            { _id: new ObjectId(residentId) },
            { $set: { archive: 0, suspend: 0 } }   // ✅ archive + suspend
        );

        if (result.modifiedCount === 1) {
            // ✅ Respond success immediately
            res.json({ success: true, message: "Resident archived & suspended successfully." });

            // 📧 Send email in the background
            if (resident.email) {
                const mailOptions = {
                    from: "johnniebre1995@gmail.com",
                    to: resident.email,
                    subject: "Account Archived & Suspended",
                    text: `Dear ${resident.firstName},\n\nWe regret to inform you that your account has been archived and suspended.\n\nThank you.`,
                    html: `<p>Dear <strong>${resident.firstName}</strong>,</p>
                           <p>We regret to inform you that your account has been <strong>archived and suspended</strong>.</p>
                           <p>If you believe this was an error, please contact your barangay office.</p>
                           <p>Thank you.</p>`,
                };

                transporter.sendMail(mailOptions)
                    .then(() => console.log("Archive + Suspension email sent to:", resident.email))
                    .catch((emailError) => console.error("Failed to send email:", emailError.message));
            }
        } else {
            res.status(404).json({ success: false, message: "Resident not found." });
        }
    } catch (error) {
        console.error("Error archiving resident:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

app.get("/updateRsd/:id", isLogin, async (req, res) => {
    try {
        if (!db) {
            return res.status(500).send("Database not connected");
        }

        const residentId = req.params.id.trim();

        // Validate ObjectId
        if (!ObjectId.isValid(residentId)) {
            return res.status(400).send("Invalid resident ID");
        }

        // Fetch the resident being updated
        const resident = await db.collection("resident").findOne(
            { _id: new ObjectId(residentId) }
        );

        if (!resident) {
            return res.status(404).send("Resident not found");
        }

        // Fetch minimal fields for head selection (faster & cleaner)
        const heads = await db.collection("resident")
            .find({}, { projection: { firstName: 1, middleName: 1, lastName: 1, extName: 1 } })
            .toArray();

        // Render update page
        res.render("updateRsd", {
            resident,   // The resident being updated
            heads,      // All residents (for headId selection dropdown)
            layout: "layout",
            title: "Update Resident",
            activePage: "rsd",
        });

    } catch (error) {
        console.error("Error in /updateRsd/:id:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/update-resident/:id", async (req, res) => {
    try {
        const residentId = req.params.id;

        if (!ObjectId.isValid(residentId)) {
            return res.status(400).send("Invalid resident ID");
        }

        // Fetch existing resident
        const existingResident = await db.collection("resident").findOne({ _id: new ObjectId(residentId) });
        if (!existingResident) {
            return res.status(404).send("Resident not found");
        }

        console.log("Existing Resident Data:", existingResident);
        console.log("New Form Data:", req.body);

        const updateFields = {};

        // Handle checkboxes explicitly
        const checkboxFields = ["soloParent", "pregnant", "pwd"];
        checkboxFields.forEach((field) => {
            const newValue = req.body[field] ? "on" : "no"; // normalize
            if (newValue !== (existingResident[field] || "no")) {
                updateFields[field] = newValue;
            }
        });

        // Handle other fields normally
        Object.keys(req.body).forEach((key) => {
            if (!checkboxFields.includes(key)) {
                if (req.body[key] && req.body[key] !== existingResident[key]) {
                    updateFields[key] = req.body[key];
                }
            }
        });

        if (Object.keys(updateFields).length === 0) {
            console.log("No changes were made.");
            return res.status(400).send("No changes were made.");
        }

        // Perform update
        await db.collection("resident").updateOne(
            { _id: new ObjectId(residentId) },
            { $set: updateFields }
        );

        console.log("Resident updated successfully.");
        res.redirect(`/resv/${residentId}`);

    } catch (error) {
        console.error("Error updating resident:", error);
        res.status(500).send("Error updating resident");
    }
});

app.post("/upload-photo/:id", upload.single("photo"), async (req, res) => {
    try {
        console.log("Request body:", req.body); // Debugging
        console.log("Uploaded file:", req.file); // Debugging

        const residentId = req.params.id;

        if (!req.file) {
            return res.status(400).send("No file uploaded.");
        }

        const photoPath = `/uploads/${req.file.filename}`;

        await db.collection("resident").updateOne(
            { _id: new ObjectId(residentId) },
            { $set: { photo: photoPath } }
        );

        res.redirect(`/resv/${residentId}`);
    } catch (err) {
        console.error("Error uploading photo:", err);
        res.status(500).send("Error uploading photo.");
    }
});

app.post("/upload-my-photo", isLogin, upload.single("image"), async (req, res) => {
  try {
    const userId = req.session.userId;
    if (!req.file || !userId) {
      return res.status(400).send("Missing file or session.");
    }

    const imageUrl = req.file.path; // Cloudinary automatically gives you the hosted URL

    // Save Cloudinary URL to database
    await db.collection("resident").updateOne(
      { _id: new ObjectId(userId) },
      { $set: { photo: imageUrl } }
    );

    res.status(200).send("Photo uploaded successfully.");
  } catch (err) {
    console.error("Error uploading photo:", err);
    res.status(500).send("Error uploading photo.");
  }
});


app.post("/add-business", async (req, res) => {
    try {
        const { businessName, businessType, ownerName, contactNumber, houseNo, purok, estDate } = req.body;

        // Validate required fields
        if (!businessName || !businessType || !ownerName || !houseNo || !purok || !estDate) {
            return res.send('<script>alert("Please fill out all required fields!"); window.location="/bss";</script>');
        }

        // Create new business data with a default archive value of 0
        const newBusiness = {
            businessName,
            businessType,
            ownerName,
            contactNumber,
            estDate,
            houseNo,
            purok,
            createdAt: new Date(),
            archive: 0  // Default to 0 (not archived)
        };

        // Insert new business into the database
        await db.collection("business").insertOne(newBusiness);

        // Redirect with success message
        res.send('<script>alert("Business added successfully!"); window.location="/bss";</script>');
    } catch (err) {
        console.error("Error adding business:", err.message);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/bss";</script>');
    }
});



app.get("/bss", isLogin, isRsd, async (req, res) => {
    try {
        const residents = await db.collection("resident")
            .find({ archive: { $in: [0, "0", 1, "1"] } })
            .sort({ firstName: 1 })
            .toArray();

        const households = await db.collection("household")
            .find({ archive: { $in: [0, "0"] } })
            .toArray();

        const families = await db.collection("family")
            .find({ archive: { $in: [0, "0"] } })
            .toArray();

        // Map household and family data
        const householdMap = new Map();
        households.forEach(household => {
            householdMap.set(String(household._id), { houseNo: household.houseNo, purok: household.purok });
        });

        const familyMap = new Map();
        families.forEach(family => {
            familyMap.set(String(family._id), { poverty: family.poverty });
        });

        // Attach household & family info to residents
        residents.forEach(resident => {
            const householdData = householdMap.get(String(resident.householdId)) || { houseNo: "-", purok: "-" };
            resident.houseNo = householdData.houseNo;
            resident.purok = householdData.purok;

            const familyData = familyMap.get(String(resident.familyId)) || { poverty: "No Income" };
            resident.familyPoverty = familyData.poverty;
        });

        // Totals
        const totalHouseholds = households.length;
        const totalFamilies = families.length;
        const totalInhabitants = residents.length;
        const totalVoters = residents.filter(r => r.precinct === "Registered Voter").length;

        // Businesses
        const businesses = await db.collection("business")
            .find({ archive: { $in: [0, "0"] } })
            .sort({ businessName: 1 })
            .toArray();

        // Map owner info
        const residentMap = new Map();
        residents.forEach(resident => residentMap.set(String(resident._id), resident));

        businesses.forEach(business => {
            const owner = residentMap.get(String(business.ownerName));
            if (owner) {
                business.owner = {
                    _id: owner._id,
                    firstName: owner.firstName,
                    lastName: owner.lastName,
                    phone: owner.phone,
                    purok: owner.purok,
                    houseNo: owner.houseNo,
                    familyPoverty: owner.familyPoverty
                };
            } else {
                business.owner = null;
            }

            // Safe estDate for EJS
            business.estDateISO = business.estDate && !isNaN(new Date(business.estDate))
                ? new Date(business.estDate).toISOString().split("T")[0]
                : "";
        });

        const totalCount = businesses.length;

        // Render
        res.render("bss", {
            layout: "layout",
            title: "Business",
            activePage: "bss",
            residents,
            totalHouseholds,
            totalFamilies,
            totalInhabitants,
            totalVoters,
            totalCount,
            businesses,  // always defined
            message: businesses.length === 0 ? "No active businesses found." : null
        });

    } catch (err) {
        console.error("Error fetching businesses:", err.message);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/";</script>');
    }
});

app.post("/update-business/:id", isLogin, async (req, res) => {
    try {
        const businessId = req.params.id;
        const { businessName, estDate, businessType, ownerName, contactNumber, houseNo, purok } = req.body;

        // Validate that required fields are provided
        if (!businessName || !estDate || !businessType || !ownerName) {
            return res.send('<script>alert("All fields are required!"); window.location="/bss";</script>');
        }

        // Check if the business ID is a valid ObjectId
        if (!ObjectId.isValid(businessId)) {
            return res.send('<script>alert("Invalid Business ID!"); window.location="/bss";</script>');
        }

        // Log the businessId and input data for debugging
        console.log("Business ID:", businessId);
        console.log("Business Data:", { businessName, estDate, businessType, ownerName, contactNumber, houseNo, purok });

        // Update the business data in the database
        const result = await db.collection("business").updateOne(
            { _id: new ObjectId(businessId) }, // Instantiate ObjectId with `new`
            { 
                $set: {
                    businessName,
                    estDate, 
                    businessType, 
                    ownerName, 
                    contactNumber, 
                    houseNo, 
                    purok,
                    updatedAt: new Date()
                }
            }
        );

        console.log("Update Result:", result); // Log the result for debugging

        // Check if any document was updated
        if (result.modifiedCount === 0) {
            return res.send('<script>alert("No changes made!"); window.location="/bss";</script>');
        }

        res.send('<script>alert("Business updated successfully!"); window.location="/bss";</script>');
    } catch (err) {
        console.error("Error updating business:", err.message);
        res.status(500).send('<script>alert("Error updating the business! Please try again."); window.location="/bss";</script>');
    }
});

app.post("/delete-business/:id", isLogin, async (req, res) => {
    try {
        const businessId = req.params.id;

        // Ensure the businessId is a valid MongoDB ObjectId
        if (!ObjectId.isValid(businessId)) {
            return res.send('<script>alert("Invalid business ID."); window.location="/bss";</script>');
        }

        // Query the business to check if it exists and is not already archived
        const business = await db.collection("business").findOne({ _id: new ObjectId(businessId) });

        if (!business) {
            return res.send('<script>alert("Business not found."); window.location="/bss";</script>');
        }

        // If the business is already archived
        if (business.archive === 1) {
            return res.send('<script>alert("This business is already archived."); window.location="/bss";</script>');
        }

        // Proceed with archiving the business
        const result = await db.collection("business").updateOne(
            { _id: new ObjectId(businessId) },
            { $set: { archive: 1 } }
        );

        if (result.modifiedCount === 0) {
            return res.send('<script>alert("Failed to archive the business. Please try again."); window.location="/bss";</script>');
        }

        res.send('<script>alert("Business archived successfully."); window.location="/bss";</script>');
    } catch (err) {
        console.error("Error archiving business:", err.message);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/bss";</script>');
    }
});

app.get("/viewBus/:id", isLogin, async (req, res) => {
  try {
    const businessId = req.params.id;
    const business = await db.collection("business").findOne({ _id: new ObjectId(businessId) });

    if (!business) {
      return res.status(404).send("Business not found!");
    }

    // Get the owner from residents
    let owner = null;
    if (business.ownerName) {
      const resident = await db.collection("resident").findOne({ _id: new ObjectId(business.ownerName) });

      if (resident) {
        // Fetch household info
        const household = resident.householdId
          ? await db.collection("household").findOne({ _id: new ObjectId(resident.householdId) })
          : null;

        // Fetch family info
        const family = resident.familyId
          ? await db.collection("family").findOne({ _id: new ObjectId(resident.familyId) })
          : null;

        owner = {
          _id: resident._id,
          firstName: resident.firstName,
          lastName: resident.lastName,
          phone: resident.phone || "-",
          purok: household?.purok || "-",
          houseNo: household?.houseNo || "-",
          familyPoverty: family?.poverty || "No Income"
        };
      }
    }

    // Safe estDate for EJS
    business.estDateISO =
      business.estDate && !isNaN(new Date(business.estDate))
        ? new Date(business.estDate).toISOString().split("T")[0]
        : "";

    // Attach owner
    business.owner = owner;

    // Render the page to display the business details
    res.render("viewBus", {
      layout: "layout",
      title: "Business",
      activePage: "bss",
      business
    });

  } catch (err) {
    console.error("Error fetching business:", err.message);
    res.status(500).send("Error fetching business.");
  }
});

app.get("/htl", isLogin, async (req, res) => {
    try {
        // Fetch hotline data where archive is 0, ordered by the 'office' field
        const hotlineData = await db.collection("hotline")
    .find({ archive: { $in: [0, "0"] } })
    .sort({ office: 1 })
    .toArray();


        // Render the page with hotline data
        res.render("htl", {
            layout: "layout",
            title: "Hotline",
            activePage: "htl",
            hotlineData: hotlineData  // Pass hotline data to EJS
        });
    } catch (err) {
        console.error("Error fetching hotline data:", err);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
    }
});

app.get("/cnt", isLogin, async (req, res) => {
    try {
        // Fetch hotline data where archive is 0, ordered by the 'office' field
        const hotlineData = await db.collection("hotline")
    .find({ archive: { $in: [0, "0"] } })
    .sort({ office: 1 })
    .toArray();


        // Render the page with hotline data
        res.render("cnt", {
            layout: "layout",
            title: "Hotline",
            activePage: "htl",
            hotlineData: hotlineData  // Pass hotline data to EJS
        });
    } catch (err) {
        console.error("Error fetching hotline data:", err);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
    }
});





app.post("/add-hotline", async (req, res) => {
    try {
        const { office, phone1, phone2, phone3, email, web } = req.body;

        // Validate required fields
        if (!office || !phone1) {
            return res.send('<script>alert("Please fill out all required fields!"); window.location="/htl";</script>');
        }

        // Create new hotline data with a default archive value of true
        const newHotline = {
            office,
            phone1,
            phone2,
            phone3,
            email,
            web,
            createdAt: new Date(),
            archive: 0  // Default to true (archived)
        };

        // Insert new hotline into the database
        await db.collection("hotline").insertOne(newHotline);

        // Redirect with success message
        res.send('<script>alert("Hotline added successfully!"); window.location="/htl";</script>');
    } catch (err) {
        console.error("Error adding hotline:", err.message);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/htl";</script>');
    }
});

app.get("/edit-hotline/:id", isLogin, async (req, res) => {
    try {
        const hotline = await Hotline.findById(req.params.id); // Assuming you're using MongoDB
        res.render("htl", {
            layout: "layout",
            title: "Hotline",
            activePage: "dsb",
            hotlineData: [hotline],  // Pass the hotline data to the view
            editMode: true          // This flag will be used to indicate edit mode
        });
    } catch (error) {
        console.log(error);
        res.status(500).send("Error fetching hotline data.");
    }
});

app.post("/update-hotline/:id", isLogin, async (req, res) => {
    try {
        const hotlineId = req.params.id; // Get the hotline ID from the URL parameter
        const { office, phone1, phone2, phone3, email, web } = req.body; // Get data from the form

        // Validate that required fields are provided (office, phone1 are required)
        if (!office || !phone1) {
            return res.send('<script>alert("Office, Phone 1 are required!"); window.location="/htl";</script>');
        }

        // Check if the hotline ID is a valid ObjectId
        if (!ObjectId.isValid(hotlineId)) {
            return res.send('<script>alert("Invalid Hotline ID!"); window.location="/htl";</script>');
        }

        // Fetch the current hotline data from the database
        const currentHotline = await db.collection("hotline").findOne({ _id: new ObjectId(hotlineId) });

        // Log the current hotline data for comparison
        console.log("Current Hotline Data:", currentHotline);

        // Log the form data to compare
        console.log("Form Data:", { office, phone1, phone2, phone3, email, web });

        // Check if any value has changed
        let changesMade = false;
        const updatedFields = {};

        // Compare form data with current data
        if (currentHotline.office !== office) {
            updatedFields.office = office;
            changesMade = true;
        }
        if (currentHotline.phone1 !== phone1) {
            updatedFields.phone1 = phone1;
            changesMade = true;
        }
        if (currentHotline.phone2 !== phone2) {
            updatedFields.phone2 = phone2;
            changesMade = true;
        }
        if (currentHotline.phone3 !== phone3) {
            updatedFields.phone3 = phone3;
            changesMade = true;
        }
        if (currentHotline.email !== email) {
            updatedFields.email = email;
            changesMade = true;
        }
        if (currentHotline.web !== web) {
            updatedFields.web = web;
            changesMade = true;
        }

        // If no changes were made, return early
        if (!changesMade) {
            return res.send('<script>alert("No changes made!"); window.location="/htl";</script>');
        }

        // Add the timestamp for update
        updatedFields.updatedAt = new Date();

        // Perform the update in the database
        const result = await db.collection("hotline").updateOne(
            { _id: new ObjectId(hotlineId) }, // Find the document by ID
            { $set: updatedFields } // Set only the updated fields
        );

        console.log("Update Result:", result); // Log the result for debugging

        // Check if any document was updated
        if (result.modifiedCount === 0) {
            return res.send('<script>alert("No changes made!"); window.location="/htl";</script>');
        }

        res.send('<script>alert("Hotline updated successfully!"); window.location="/htl";</script>');
    } catch (err) {
        console.error("Error updating hotline:", err.message);
        res.status(500).send('<script>alert("Error updating the hotline! Please try again."); window.location="/htl";</script>');
    }
});

app.get("/archive-htl/:id", isLogin, async (req, res) => {
    try {
        const hotlineId = req.params.id; // Get the hotline ID from the URL parameter

        // Check if the hotline ID is a valid ObjectId
        if (!ObjectId.isValid(hotlineId)) {
            return res.send('<script>alert("Invalid Hotline ID!"); window.location="/htl";</script>');
        }

        // Update the status of the hotline to 1 (archived)
        const result = await db.collection("hotline").updateOne(
            { _id: new ObjectId(hotlineId) }, // Find the hotline by ID
            { $set: { archive: 1, updatedAt: new Date() } } // Set the status to archived (1)
        );

        if (result.modifiedCount === 0) {
            return res.send('<script>alert("Failed to archive the hotline!"); window.location="/htl";</script>');
        }

        res.send('<script>alert("Hotline archived successfully!"); window.location="/htl";</script>');
    } catch (err) {
        console.error("Error archiving hotline:", err.message);
        res.status(500).send('<script>alert("Error archiving the hotline! Please try again."); window.location="/htl";</script>');
    }
});
app.get("/hom", isLogin, isAnn, myReq, async (req, res) => {
    console.log("🔐 User Access Level:", req.session.access);
    console.log("📌 Session Data:", req.session);

    if (req.session.access !== 0) return res.redirect("/");

    try {
        const userId = req.session.userId;
        if (!userId) throw new Error("User ID not found in session.");

        const userObjectId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;
        console.log("👤 Logged-in User ID:", userObjectId);

        // 🔍 Check if resident has reset = 1
        const resident = await db.collection("resident").findOne({ _id: userObjectId });
        if (resident && (resident.reset === 1 || resident.reset === "1")) {
            console.log("⚠️ Reset flag found. Redirecting to /prf...");
            return res.redirect("/prf");
        }

        // Fetch Complainee Cases where logged-in user is in the "name" array
        const complaineeCases = await db.collection("complainees").find({ 
            name: { $in: [userObjectId, userId] }
        }).toArray();

        console.log("📌 Complainee Cases Found:", complaineeCases.length);

        const caseObjectIds = [...new Set(complaineeCases.map(c => c.caseId))]
            .filter(id => ObjectId.isValid(id))
            .map(id => new ObjectId(id));

        console.log("⚖️ Matched Case IDs:", caseObjectIds);

        const pendingCases = caseObjectIds.length
            ? await db.collection("cases").countDocuments({ 
                _id: { $in: caseObjectIds }, 
                status: { $regex: /^pending$/i } 
            })
            : 0;

        console.log("📌 Pending Cases Count:", pendingCases);

        res.render("hom", {
            layout: "layout",
            title: "Home",
            activePage: "home",
            pendingCases,
        });

    } catch (error) {
        console.error("❌ Error fetching pending cases:", error.message);
        res.status(500).send("Internal Server Error");
    }
});


app.get("/reqM", isLogin, isAnn, myReq, async (req, res) => {
    console.log("🔐 User Access Level:", req.session.access);
    console.log("📌 Session Data:", req.session);

    if (req.session.access !== 0) return res.redirect("/");

    try {
        const userId = req.session.userId;
        if (!userId) throw new Error("User ID not found in session.");

        // Convert userId to ObjectId if valid
        const userObjectId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

        console.log("👤 Logged-in User ID:", userObjectId);

        // Fetch Complainee Cases where logged-in user is in the "name" array
        const complaineeCases = await db.collection("complainees").find({ 
            name: { $in: [userObjectId, userId] }  // ✅ Matches either ObjectId or string
        }).toArray();

        console.log("📌 Complainee Cases Found:", complaineeCases.length);

        // Collect unique case IDs
        const caseObjectIds = [...new Set(complaineeCases.map(c => c.caseId))]
            .filter(id => ObjectId.isValid(id))
            .map(id => new ObjectId(id));

        console.log("⚖️ Matched Case IDs:", caseObjectIds);

        // Fetch 'Pending' cases
        const pendingCases = caseObjectIds.length
            ? await db.collection("cases").countDocuments({ _id: { $in: caseObjectIds }, status: { $regex: /^pending$/i } })
            : 0;

        console.log("📌 Pending Cases Count:", pendingCases);

        res.render("reqM", {
            layout: "layout",
            title: "Home",
            activePage: "home",
            pendingCases,
        });

    } catch (error) {
        console.error("❌ Error fetching pending cases:", error.message);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/mainReq", isLogin, isAnn, myReq, isRsd, async (req, res) => {
    console.log("🔐 User Access Level:", req.session.access);
    console.log("📌 Session Data:", req.session);

    if (req.session.access !== 1) return res.redirect("/");

    try {
        const userId = req.session.userId;
        if (!userId) throw new Error("User ID not found in session.");

        // Convert userId to ObjectId if valid
        const userObjectId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

        console.log("👤 Logged-in User ID:", userObjectId);

        // Fetch Complainee Cases where logged-in user is in the "name" array
        const complaineeCases = await db.collection("complainees").find({ 
            name: { $in: [userObjectId, userId] }  // ✅ Matches either ObjectId or string
        }).toArray();

        console.log("📌 Complainee Cases Found:", complaineeCases.length);

        // Collect unique case IDs
        const caseObjectIds = [...new Set(complaineeCases.map(c => c.caseId))]
            .filter(id => ObjectId.isValid(id))
            .map(id => new ObjectId(id));

        console.log("⚖️ Matched Case IDs:", caseObjectIds);

        // Fetch 'Pending' cases
        const pendingCases = caseObjectIds.length
            ? await db.collection("cases").countDocuments({ _id: { $in: caseObjectIds }, status: { $regex: /^pending$/i } })
            : 0;

        console.log("📌 Pending Cases Count:", pendingCases);

        res.render("mainReq", {
            layout: "layout",
            title: "Home",
            activePage: "home",
            pendingCases,
        });

    } catch (error) {
        console.error("❌ Error fetching pending cases:", error.message);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/terms", isLogin, isAnn, myReq, async (req, res) => {
    console.log("🔐 User Access Level:", req.session.access);
    console.log("📌 Session Data:", req.session);

    if (req.session.access !== 0) return res.redirect("/");

    try {
        const userId = req.session.userId;
        if (!userId) throw new Error("User ID not found in session.");

        // Convert userId to ObjectId if valid
        const userObjectId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

        console.log("👤 Logged-in User ID:", userObjectId);

        // Fetch Complainee Cases where logged-in user is in the "name" array
        const complaineeCases = await db.collection("complainees").find({ 
            name: { $in: [userObjectId, userId] }  // ✅ Matches either ObjectId or string
        }).toArray();

        console.log("📌 Complainee Cases Found:", complaineeCases.length);

        // Collect unique case IDs
        const caseObjectIds = [...new Set(complaineeCases.map(c => c.caseId))]
            .filter(id => ObjectId.isValid(id))
            .map(id => new ObjectId(id));

        console.log("⚖️ Matched Case IDs:", caseObjectIds);

        // Fetch 'Pending' cases
        const pendingCases = caseObjectIds.length
            ? await db.collection("cases").countDocuments({ _id: { $in: caseObjectIds }, status: { $regex: /^pending$/i } })
            : 0;

        console.log("📌 Pending Cases Count:", pendingCases);

        res.render("terms", {
            layout: "layout",
            title: "Home",
            activePage: "home",
            pendingCases,
        });

    } catch (error) {
        console.error("❌ Error fetching pending cases:", error.message);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/reqAll", isLogin, isAnn, myReq, isRsd, (req, res) => {
    console.log("User Access Level:", req.session.access);  // Log the access level
    if (req.session.access !== 0) return res.redirect("/reqAll"); // If access is not 0, redirect to home
    res.render("reqAll", { layout: "layout", title: "Home", activePage: "home" });
});


app.get("/req", isLogin, isAnn, myReq, (req, res) => {
    console.log("User Access Level:", req.session.access);  // Log the access level
    if (req.session.access !== 0) return res.redirect("/"); // If access is not 0, redirect to home
    res.render("hom", { layout: "layout", title: "req", activePage: "req" });
});

app.get("/reqSuccess", isLogin, isReq, (req, res) => res.render("reqSuccess", { layout: "design", title: "Services", activePage: "reqSuccess" }));
app.get("/reqSuccessA", isLogin, isReq, (req, res) => res.render("reqSuccessA", { layout: "design", title: "Services", activePage: "reqSuccessA" }));

const storage2 = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "public/uploads/proofs/");
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname); // keep original extension
        const uniqueName = Date.now() + "-" + Math.round(Math.random() * 1E9) + ext;
        cb(null, uniqueName);
    }
});

const upload2 = multer({
    storage: storage2,
    fileFilter: (req, file, cb) => {
        const allowed = /jpeg|jpg|png|pdf|doc|docx/;
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowed.test(ext)) {
            cb(null, true);
        } else {
            cb(new Error("Only images, PDF, and DOC/DOCX files are allowed!"), false);
        }
    }
});


app.post("/reqDocument", isLogin, upload2.array("proof[]"), async (req, res) => {
  const sessionUserId = req.user._id; // Logged-in user ID

  try {
    console.log("Request Body:", req.body);

    let { type, qty, purpose, remarks, remarkMain, requestFor } = req.body;

    // Upload proof files to Cloudinary
    let proof = [];
    if (req.files && req.files.length > 0) {
      const uploadPromises = req.files.map(file =>
        cloudinary.uploader.upload(file.path, {
          folder: "barangay_proofs", // Cloudinary folder name
          resource_type: "image"
        })
      );

      const results = await Promise.all(uploadPromises);
      proof = results.map(r => r.secure_url); // Cloudinary hosted URLs
    }

    // Ensure all inputs are arrays
    type = [].concat(type);
    qty = [].concat(qty).map(Number);
    purpose = [].concat(purpose);
    requestFor = [].concat(requestFor);
    remarks = [].concat(remarks || []);
    remarkMain = remarkMain || "";

    console.log("Processed Data:", { type, qty, purpose, requestFor, proof, remarks, remarkMain });

    // Validate lengths
    if (type.length !== qty.length || type.length !== purpose.length || type.length !== requestFor.length) {
      return res.status(400).send('<script>alert("Mismatch in document fields! Please try again."); window.location="/hom";</script>');
    }

    if (!type.length || !qty.length || !purpose.length) {
      return res.status(400).send('<script>alert("Please fill out all required fields."); window.location="/hom";</script>');
    }

    // Fetch logged-in resident for email + indigent
    const resident = await db.collection("resident").findOne({ _id: new ObjectId(sessionUserId) });
    const residentIndigent = resident?.indigent || "";

    // Manila time helper
    const manilaNow = () => new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Manila" }));

    // Prepare documents to insert
    const docsToInsert = type.map((docType, i) => {
      const date = manilaNow();
      const yyyy = date.getFullYear();
      const mm = String(date.getMonth() + 1).padStart(2, "0");
      const dd = String(date.getDate()).padStart(2, "0");
      const formattedDate = `${yyyy}${mm}${dd}`;
      const randomChars = Math.random().toString(36).substring(2, 8);
      const tr = `DOC-${formattedDate}-${randomChars}`;

      let status = "Pending";
      if (docType === "Barangay Indigency") {
        status = "Pending"; // You can adjust logic if needed
      }

      // Convert requestFor to ObjectId
      const requestForId = requestFor[i] ? new ObjectId(requestFor[i]) : new ObjectId(sessionUserId);

      return {
        tr,
        createdAt: date,
        updatedAt: date,
        status,
        archive: 0,
        requestBy: new ObjectId(sessionUserId),
        requestFor: requestForId,
        remarkMain,
        remarks: remarks[i] || "",
        type: docType,
        qty: qty[i] || 1,
        purpose: purpose[i] || "",
        proof: proof[i] || "" // Cloudinary URL if uploaded
      };
    });

    // Insert all documents
    await db.collection("request").insertMany(docsToInsert);

    // Send email notification
    if (resident?.email) {
      const mailOptions = {
        from: '"Barangay San Andres" <johnniebre1995@gmail.com>',
        to: resident.email,
        subject: "Document Request Submitted Successfully",
        html: `
          <p style="font-size: 18px; text-align: center;">Your request has been submitted successfully!</p>
          <div style="font-size: 14px; text-align: center; font-weight: 500;">
            The Barangay Secretary will review your request within 24 hours on business days and will notify you via email regarding its status. Weekends are excluded.
          </div>
        `,
      };

      try {
        await transporter.sendMail(mailOptions);
        console.log("Email sent to:", resident.email);
      } catch (emailError) {
        console.error("Error sending email:", emailError);
      }
    }

    // Redirect to success page
    res.redirect("/reqSuccess");

  } catch (err) {
    console.error("Error inserting request:", err);
    res.status(500).send('<script>alert("Error inserting request! Please try again."); window.location="/hom";</script>');
  }
});

app.post("/reqDocumentA", isLogin, upload2.array("proof[]"), async (req, res) => {
  const sessionUserId = req.user._id; // Logged-in user ID

  try {
    console.log("Request Body:", req.body);

    let { type, qty, purpose, remarks, remarkMain, requestFor } = req.body;

    // Upload proof files to Cloudinary
    let proof = [];
    if (req.files && req.files.length > 0) {
      const uploadPromises = req.files.map(file =>
        cloudinary.uploader.upload(file.path, {
          folder: "barangay_proofs", // store inside this Cloudinary folder
          resource_type: "image",
        })
      );
      const results = await Promise.all(uploadPromises);
      proof = results.map(r => r.secure_url); // save Cloudinary URLs
    }

    // Ensure all inputs are arrays
    type = [].concat(type);
    qty = [].concat(qty).map(Number);
    purpose = [].concat(purpose);
    requestFor = [].concat(requestFor);
    remarks = [].concat(remarks || []);
    remarkMain = remarkMain || "";

    console.log("Processed Data:", { type, qty, purpose, requestFor, proof, remarks, remarkMain });

    // Validate lengths
    if (type.length !== qty.length || type.length !== purpose.length || type.length !== requestFor.length) {
      return res.status(400).send('<script>alert("Mismatch in document fields! Please try again."); window.location="/hom";</script>');
    }

    if (!type.length || !qty.length || !purpose.length) {
      return res.status(400).send('<script>alert("Please fill out all required fields."); window.location="/hom";</script>');
    }

    // Fetch logged-in resident for email + indigent
    const resident = await db.collection("resident").findOne({ _id: new ObjectId(sessionUserId) });
    const residentIndigent = resident?.indigent || "";

    // Manila time helper
    const manilaNow = () => new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Manila" }));

    // Prepare documents to insert
    const docsToInsert = type.map((docType, i) => {
      const date = manilaNow();
      const yyyy = date.getFullYear();
      const mm = String(date.getMonth() + 1).padStart(2, "0");
      const dd = String(date.getDate()).padStart(2, "0");
      const formattedDate = `${yyyy}${mm}${dd}`;
      const randomChars = Math.random().toString(36).substring(2, 8);
      const tr = `DOC-${formattedDate}-${randomChars}`;

      let status = "Pending";
      if (docType === "Barangay Indigency") {
        status = "Pending"; // can adjust based on residentIndigent
      }

      // Convert requestFor to ObjectId
      const requestForId = requestFor[i] ? new ObjectId(requestFor[i]) : new ObjectId(sessionUserId);

      return {
        tr,
        createdAt: date,
        updatedAt: date,
        status,
        archive: 0,
        requestBy: new ObjectId(sessionUserId),
        requestFor: requestForId,
        remarkMain,
        remarks: remarks[i] || "",
        type: docType,
        qty: qty[i] || 1,
        purpose: purpose[i] || "",
        proof: proof[i] || "", // Cloudinary URL if uploaded
      };
    });

    // Insert all documents
    await db.collection("request").insertMany(docsToInsert);

    // Send email notification
    if (resident?.email) {
      const mailOptions = {
        from: '"Barangay San Andres" <johnniebre1995@gmail.com>',
        to: resident.email,
        subject: "Document Request Submitted Successfully",
        html: `
          <p style="font-size: 18px; text-align: center;">Your request has been submitted successfully!</p>
          <div style="font-size: 14px; text-align: center; font-weight: 500;">
            The Barangay Secretary will review your request within 24 hours on business days and will notify you via email regarding its status. Weekends are excluded.
          </div>
        `,
      };

      try {
        await transporter.sendMail(mailOptions);
        console.log("Email sent to:", resident.email);
      } catch (emailError) {
        console.error("Error sending email:", emailError);
      }
    }

    // Redirect to success page
    res.redirect("/reqSuccessA");

  } catch (err) {
    console.error("Error inserting request:", err);
    res.status(500).send('<script>alert("Error inserting request! Please try again."); window.location="/hom";</script>');
  }
});

app.get("/api/residents", async (req, res) => {
    try {
        const residents = await db.collection("resident").find({}).toArray();
        res.json(residents);
    } catch (error) {
        console.error("Error fetching residents:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});


app.get("/srv", isLogin, isReq, (req, res) => res.render("srv", { layout: "layout", title: "Services", activePage: "srv" }));
app.get("/ovv", isLogin, isReq, (req, res) => res.render("ovv", { layout: "layout", title: "Overview", activePage: "ovv" }));
app.get("/ovvB", isLogin, isReq, (req, res) => res.render("ovvB", { layout: "layout", title: "Clearance", activePage: "ovvB" }));
app.get("/ovvI", isLogin, isReq, (req, res) => res.render("ovvI", { layout: "layout", title: "Indigency", activePage: "ovvI" }));
app.get("/ovvR", isLogin, isReq, (req, res) => res.render("ovvR", { layout: "layout", title: "Residency", activePage: "ovvR" }));
app.get("/ovvG", isLogin, isReq, (req, res) => res.render("ovvG", { layout: "layout", title: "Good Moral", activePage: "ovvG" }));
app.get("/ovvC", isLogin, isReq, isRsd, (req, res) => res.render("ovvC", { layout: "layout", title: "Certification", activePage: "ovvC" }));
app.get("/docc", isLogin, isReq, (req, res) => res.render("docc", { layout: "layout", title: "Document", activePage: "docc" }));

app.get("/das", isLogin, isReq, async (req, res) => {
  try {
    const {
      filterDate,
      filterType,
      filterPurpose,
      filterGender,
      filterEmployment,
      filterPriority
    } = req.query;

    const requestCollection = db.collection("request");
    const now = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Manila" }));
    const y = now.getFullYear(), m = now.getMonth(), d = now.getDate(), day = now.getDay();

    // Base match
    let matchRequest = { archive: 0 };
    let timeGroup;

    // Date filtering
    if (filterDate) {
      if (filterDate === "today") {
        matchRequest.createdAt = { 
          $gte: new Date(y, m, d), 
          $lte: new Date(y, m, d, 23, 59, 59, 999) 
        };
        timeGroup = { $hour: { date: "$createdAt", timezone: "Asia/Manila" } };
      } else if (filterDate === "week") {
        const start = new Date(now); start.setDate(d - day); start.setHours(0,0,0,0);
        const end = new Date(start); end.setDate(start.getDate() + 6); end.setHours(23,59,59,999);
        matchRequest.createdAt = { $gte: start, $lte: end };
        timeGroup = { $dayOfWeek: { date: "$createdAt", timezone: "Asia/Manila" } };
      } else if (filterDate === "month") {
        const start = new Date(y, m, 1);
        const end = new Date(y, m + 1, 0, 23, 59, 59, 999);
        matchRequest.createdAt = { $gte: start, $lte: end };
        timeGroup = { $dayOfMonth: { date: "$createdAt", timezone: "Asia/Manila" } };
      } else if (filterDate === "year") {
        const start = new Date(y, 0, 1);
        const end = new Date(y, 11, 31, 23, 59, 59, 999);
        matchRequest.createdAt = { $gte: start, $lte: end };
        timeGroup = { $month: { date: "$createdAt", timezone: "Asia/Manila" } };
      }
    }

    if (filterType) matchRequest.type = filterType;
    if (filterPurpose) matchRequest.purpose = filterPurpose;

    // Base pipeline
    const basePipeline = [
      { $match: matchRequest },
      {
        $lookup: {
          from: "resident",
          localField: "requestFor",
          foreignField: "_id",
          as: "residentArr"
        }
      },
      { $unwind: { path: "$residentArr", preserveNullAndEmptyArrays: true } },
      {
        $addFields: {
          "residentArr.age": {
            $subtract: [
              new Date().getFullYear(),
              { $toInt: { $ifNull: ["$residentArr.bYear", 0] } }
            ]
          }
        }
      },
      ...(filterGender ? [{ $match: { "residentArr.gender": filterGender } }] : []),
      ...(filterEmployment ? [{ $match: { "residentArr.employmentStatus": filterEmployment } }] : []),
      ...(filterPriority ? [{
        $match: {
          $or: [
            { "residentArr.pregnant": "on" },
            { "residentArr.pwd": "on" },
            { "residentArr.soloParent": "on" }
          ]
        }
      }] : [])
    ];

    // Chart data
    const chartPipeline = [
      ...basePipeline,
      ...(timeGroup
        ? [{ $group: { _id: { time: timeGroup, status: "$status" }, count: { $sum: 1 } } }]
        : [{ $group: { _id: { status: "$status" }, count: { $sum: 1 } } }]
      )
    ];

    const chartData = await requestCollection.aggregate(chartPipeline).toArray();

    // Totals & percentages
    const totals = chartData.reduce((acc, item) => {
      const status = item._id.status;
      acc[status] = (acc[status] || 0) + item.count;
      return acc;
    }, {});
    const grandTotal = Object.values(totals).reduce((a,b) => a+b, 0);
    const percentages = {};
    for (const [status, count] of Object.entries(totals)) {
      percentages[status] = grandTotal ? ((count / grandTotal) * 100).toFixed(2) : 0;
    }

    // Insights
    const insights = {};

    // Top Requestors
    insights.topRequestors = await requestCollection.aggregate([
      ...basePipeline,
      {
        $group: {
          _id: "$requestFor",
          count: { $sum: 1 },
          firstName: { $first: "$residentArr.firstName" },
          lastName: { $first: "$residentArr.lastName" },
          age: { $first: "$residentArr.age" },
          purok: { $first: "$residentArr.purok" }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 3 },
      {
        $project: {
          name: {
            $cond: [
              { $and: [ { $ne: ["$firstName", null] }, { $ne: ["$lastName", null] } ] },
              { $concat: ["$firstName", " ", "$lastName"] },
              "Unknown"
            ]
          },
          age: 1,
          purok: 1,
          count: 1
        }
      }
    ]).toArray();

    // Top Ages
    insights.topAges = await requestCollection.aggregate([
      ...basePipeline,
      { $group: { _id: "$residentArr.age", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 3 }
    ]).toArray();

    // Top Purok
    insights.topPurok = await requestCollection.aggregate([
      ...basePipeline,
      { $group: { _id: "$residentArr.purok", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 3 }
    ]).toArray();

    // Top Days
    insights.topDays = await requestCollection.aggregate([
      ...basePipeline,
      { $group: { _id: { $dayOfWeek: { date: "$createdAt", timezone: "Asia/Manila" } }, count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 3 }
    ]).toArray();

    // === Basic Prediction / Smoothing example ===
    const totalRequests = await requestCollection.countDocuments(matchRequest);
    insights.prediction = Math.round(totalRequests * 1.05); // +5% estimate
    insights.smoothing = "Simple Exponential"; // placeholder
    insights.avg = Math.round(totalRequests / 12);
    insights.highestMonth = "N/A"; // you can compute based on month aggregation
    insights.highest = 0;
    insights.lowestMonth = "N/A";
    insights.lowest = 0;
    insights.momChange = 0;

    // Respond
    if (req.get("X-Requested-With") === "fetch") {
      return res.json({ chartData, totals, percentages, grandTotal, insights });
    }

    res.render("das", {
      layout: "layout",
      title: "Dashboard",
      activePage: "das",
      chartData,
      totals,
      percentages,
      grandTotal,
      insights,
      filters: { filterDate, filterType, filterPurpose, filterGender, filterEmployment, filterPriority }
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

app.get("/api/das-data", isLogin, isReq, async (req, res) => {
  try {
    const {
      filterDate,
      filterType,
      filterPurpose,
      filterGender,
      filterEmployment,
      filterPriority
    } = req.query;

    const requestCollection = db.collection("request");
    const now = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Manila" }));
    const y = now.getFullYear(), m = now.getMonth(), d = now.getDate(), day = now.getDay();

    let matchRequest = { archive: 0 };
    let timeGroup = null;

    // === Date filtering ===
    if (filterDate === "today") {
      matchRequest.createdAt = { $gte: new Date(y, m, d), $lte: new Date(y, m, d, 23, 59, 59, 999) };
      timeGroup = { $hour: { date: "$createdAt", timezone: "Asia/Manila" } };
    } else if (filterDate === "week") {
      const start = new Date(now); start.setDate(d - day); start.setHours(0,0,0,0);
      const end = new Date(start); end.setDate(start.getDate() + 6); end.setHours(23,59,59,999);
      matchRequest.createdAt = { $gte: start, $lte: end };
      timeGroup = { $dayOfWeek: { date: "$createdAt", timezone: "Asia/Manila" } };
    } else if (filterDate === "month") {
      const start = new Date(y, m, 1), end = new Date(y, m + 1, 0, 23, 59, 59, 999);
      matchRequest.createdAt = { $gte: start, $lte: end };
      timeGroup = { $dayOfMonth: { date: "$createdAt", timezone: "Asia/Manila" } };
    } else if (filterDate === "year") {
      const start = new Date(y, 0, 1), end = new Date(y, 11, 31, 23, 59, 59, 999);
      matchRequest.createdAt = { $gte: start, $lte: end };
      timeGroup = { $month: { date: "$createdAt", timezone: "Asia/Manila" } };
    } 
    // "All" case does NOT modify matchRequest or timeGroup — we group by year in pipeline

    // === Type & purpose filters ===
    if (filterType) matchRequest.type = filterType;
    if (filterPurpose) matchRequest.purpose = filterPurpose;

    // === Base pipeline with resident lookup ===
    const basePipeline = [
      { $match: matchRequest },
      {
        $lookup: {
          from: "resident",
          localField: "requestFor",
          foreignField: "_id",
          as: "residentArr"
        }
      },
      { $unwind: { path: "$residentArr", preserveNullAndEmptyArrays: true } },
      {
        $addFields: {
          "residentArr.age": {
            $subtract: [
              new Date().getFullYear(),
              { $toInt: { $ifNull: ["$residentArr.bYear", 0] } }
            ]
          }
        }
      },
      ...(filterGender ? [{ $match: { "residentArr.gender": filterGender } }] : []),
      ...(filterEmployment ? [{ $match: { "residentArr.employmentStatus": filterEmployment } }] : []),
      ...(filterPriority ? [{
        $match: {
          $or: [
            { "residentArr.pregnant": "on" },
            { "residentArr.pwd": "on" },
            { "residentArr.soloParent": "on" }
          ]
        }
      }] : [])
    ];

    // === Chart pipeline ===
    const chartPipeline = [
      ...basePipeline,
      {
        $group: {
          _id: (filterDate === "all" || !filterDate)
            ? { time: { $year: "$createdAt" }, status: "$status" } // group by year
            : timeGroup
              ? { time: timeGroup, status: "$status" }           // other filters
              : { status: "$status" },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id.time": 1, "_id.status": 1 } }
    ];

    const chartData = await requestCollection.aggregate(chartPipeline).toArray();

    // === Totals & percentages ===
    const totals = chartData.reduce((acc, item) => {
      const status = item._id.status;
      acc[status] = (acc[status] || 0) + item.count;
      return acc;
    }, {});
    const grandTotal = Object.values(totals).reduce((a,b) => a+b, 0);
    const percentages = {};
    for (const [status, count] of Object.entries(totals)) {
      percentages[status] = grandTotal ? ((count / grandTotal) * 100).toFixed(2) : 0;
    }

    // === Insights === (unchanged)
    const insights = {};
    // Top Requestors
    insights.topRequestors = await requestCollection.aggregate([
      ...basePipeline,
      {
        $group: {
          _id: "$requestFor",
          count: { $sum: 1 },
          firstName: { $first: "$residentArr.firstName" },
          lastName: { $first: "$residentArr.lastName" },
          age: { $first: "$residentArr.age" },
          purok: { $first: "$residentArr.purok" }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 3 },
      {
        $project: {
          name: {
            $cond: [
              { $and: [ { $ne: ["$firstName", null] }, { $ne: ["$lastName", null] } ] },
              { $concat: ["$firstName", " ", "$lastName"] },
              "Unknown"
            ]
          },
          age: 1,
          purok: 1,
          count: 1
        }
      }
    ]).toArray();

    // Top Ages
    insights.topAges = await requestCollection.aggregate([
      ...basePipeline,
      { $group: { _id: "$residentArr.age", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 3 }
    ]).toArray();

    // Top Purok
    insights.topPurok = await requestCollection.aggregate([
      ...basePipeline,
      { $group: { _id: "$residentArr.purok", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 3 }
    ]).toArray();

    // Top Days
    insights.topDays = await requestCollection.aggregate([
      ...basePipeline,
      { $group: { _id: { $dayOfWeek: { date: "$createdAt", timezone: "Asia/Manila" } }, count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 3 }
    ]).toArray();

    // === Prediction & smoothing ===
    const totalRequests = await requestCollection.countDocuments(matchRequest);
    insights.prediction = Math.round(totalRequests * 1.05);
    insights.smoothing = "Simple Exponential";
    insights.avg = Math.round(totalRequests / 12);
    insights.highestMonth = "N/A";
    insights.highest = 0;
    insights.lowestMonth = "N/A";
    insights.lowest = 0;
    insights.momChange = 0;
    const getFilteredPipeline = () => [...basePipeline];
// === Requests per Document ===
let chartPerDocument = await requestCollection.aggregate([
  ...getFilteredPipeline(),
  { $group: { _id: "$type", count: { $sum: 1 } } },
  { $sort: { _id: 1 } }
]).toArray();
chartPerDocument = chartPerDocument.map(item => ({
  ...item,
  percentage: totalRequests > 0 ? ((item.count / totalRequests) * 100).toFixed(2) : 0
}));

// === Requests per Employment Status ===
let chartPerEmployment = await requestCollection.aggregate([
  ...getFilteredPipeline(),
  { $group: { _id: "$residentArr.employmentStatus", count: { $sum: 1 } } },
  { $sort: { _id: 1 } }
]).toArray();
chartPerEmployment = chartPerEmployment.map(item => ({
  ...item,
  percentage: totalRequests > 0 ? ((item.count / totalRequests) * 100).toFixed(2) : 0
}));

// === Requests per Gender ===
let chartPerGender = await requestCollection.aggregate([
  ...getFilteredPipeline(),
  { $group: { _id: "$residentArr.gender", count: { $sum: 1 } } },
  { $sort: { _id: 1 } }
]).toArray();
chartPerGender = chartPerGender.map(item => ({
  ...item,
  percentage: totalRequests > 0 ? ((item.count / totalRequests) * 100).toFixed(2) : 0
}));

// === Requests per Priority Group ===
let chartPerPriority = await requestCollection.aggregate([
  ...getFilteredPipeline(),
  {
    $project: {
      pregnant: "$residentArr.pregnant",
      pwd: "$residentArr.pwd",
      soloParent: "$residentArr.soloParent"
    }
  },
  {
    $group: {
      _id: null,
      pregnant: { $sum: { $cond: [{ $eq: ["$pregnant", "on"] }, 1, 0] } },
      pwd: { $sum: { $cond: [{ $eq: ["$pwd", "on"] }, 1, 0] } },
      soloParent: { $sum: { $cond: [{ $eq: ["$soloParent", "on"] }, 1, 0] } }
    }
  }
]).toArray();
if (chartPerPriority.length) {
  const row = chartPerPriority[0];
  chartPerPriority = [
    { _id: "Pregnant", count: row.pregnant, percentage: totalRequests > 0 ? ((row.pregnant / totalRequests) * 100).toFixed(2) : 0 },
    { _id: "PWD", count: row.pwd, percentage: totalRequests > 0 ? ((row.pwd / totalRequests) * 100).toFixed(2) : 0 },
    { _id: "Solo Parent", count: row.soloParent, percentage: totalRequests > 0 ? ((row.soloParent / totalRequests) * 100).toFixed(2) : 0 }
  ];
}

// === Requests per PWD Type ===
let chartPerPWDType = await requestCollection.aggregate([
  ...getFilteredPipeline(),
  { $group: { _id: "$residentArr.pwdType", count: { $sum: 1 } } },
  { $sort: { _id: 1 } }
]).toArray();
chartPerPWDType = chartPerPWDType.map(item => ({
  ...item,
  percentage: totalRequests > 0 ? ((item.count / totalRequests) * 100).toFixed(2) : 0
}));

// === Complete Request List ===
const requestList = await requestCollection.aggregate([
  ...basePipeline,
  {
    $project: {
      createdAt: 1,
      status: 1,
      tr: 1,
      type: 1,
      quantity: "$qty",
      purpose: 1,
      // Request By (owner of request)
      requestBy: {
        $concat: [
          { $ifNull: ["$requestBy.firstName", ""] }, " ",
          { $ifNull: ["$requestBy.middleName", ""] }, " ",
          { $ifNull: ["$requestBy.lastName", ""] }, " ",
          { $ifNull: ["$requestBy.extName", ""] }
        ]
      },
      // Request For (person the request is for)
      requestFor: {
        $concat: [
          { $ifNull: ["$residentArr.firstName", ""] }, " ",
          { $ifNull: ["$residentArr.middleName", ""] }, " ",
          { $ifNull: ["$residentArr.lastName", ""] }, " ",
          { $ifNull: ["$residentArr.extName", ""] }
        ]
      },
      age: "$residentArr.age",
      gender: "$residentArr.gender",
      employmentStatus: "$residentArr.employmentStatus",
      priority: {
        $cond: [
          { $or: [
            { $eq: ["$residentArr.pregnant", "on"] },
            { $eq: ["$residentArr.pwd", "on"] },
            { $eq: ["$residentArr.soloParent", "on"] }
          ]},
          "Yes",
          "No"
        ]
      }
    }
  }
]).toArray();

    res.json({
  chartData,
  totals,
  percentages,
  grandTotal,
  insights,
  chartPerDocument,
  chartPerEmployment,
  chartPerGender,
  chartPerPriority,
  chartPerPWDType,
  requestList
});

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});


app.get("/srvAll", isLogin, isReq, (req, res) => res.render("srvAll", { layout: "layout", title: "Services", activePage: "srv" }));

app.get('/doccv/:id', isLogin, async (req, res) => {
    try {
        const requestId = req.params.id;

        // ✅ Validate requestId
        if (!ObjectId.isValid(requestId)) {
            return res.status(400).send("Invalid Request ID");
        }

        // ✅ Fetch main request
        const request = await db.collection("request").findOne({
            _id: new ObjectId(requestId),
            archive: { $in: [0, "0"] }
        });

        if (!request) return res.status(404).send("Request not found");

        // ✅ Fetch resident (requestBy)
        const resident = await db.collection("resident").findOne({
            _id: new ObjectId(request.requestBy)
        });
        if (!resident) return res.status(404).send("Resident not found");

        // ✅ Household & Family
        const [household, family] = await Promise.all([
            resident.householdId ? db.collection("household").findOne({ _id: new ObjectId(resident.householdId) }) : null,
            resident.familyId ? db.collection("family").findOne({ _id: new ObjectId(resident.familyId) }) : null
        ]);

        // ✅ Cases involving resident
        const cases = await db.collection("cases").find({
            $or: [
                { respondents: new ObjectId(resident._id), archive: { $in: [0, "0"] } },
                { complainants: new ObjectId(resident._id), archive: { $in: [0, "0"] } }
            ]
        }).toArray();

        // ✅ Gather all involved person IDs
        const allPersonIds = [
            ...new Set(cases.flatMap(c => [...c.respondents, ...c.complainants]))
        ].map(id => new ObjectId(id));

        // ✅ Fetch details of complainants & respondents
        const persons = allPersonIds.length > 0
            ? await db.collection("resident").find({ _id: { $in: allPersonIds } }).toArray()
            : [];

        // ✅ Map resident data into cases
        cases.forEach(c => {
            c.respondents = c.respondents.map(rid => persons.find(p => p._id.equals(rid)) || {});
            c.complainants = c.complainants.map(rid => persons.find(p => p._id.equals(rid)) || {});
        });

        // ✅ Fetch schedules for all cases
        const caseIds = cases.map(c => new ObjectId(c._id));
        const schedules = caseIds.length > 0
            ? await db.collection("schedule").find({ caseId: { $in: caseIds.map(id => id.toString()) } }).toArray()
            : [];

        // ✅ Handle requestFor (inside request itself, not documents)
        let requestForData = null;
        if (request.requestFor) {
            let requestForId;
            if (ObjectId.isValid(request.requestFor)) {
                requestForId = new ObjectId(request.requestFor);
            } else if (typeof request.requestFor === "object" && request.requestFor._id) {
                requestForId = new ObjectId(request.requestFor._id);
            }
            if (requestForId) {
                requestForData = await db.collection("resident").findOne({ _id: requestForId });
            }
        }

        // ✅ Build final request object
        request.resident = { ...resident, household, family };
        request.requestForData = requestForData;
        request.cases = cases;
        request.schedules = schedules;

        res.render("doccv", {
            request,
            layout: "layout",
            title: "View Request",
            activePage: "docc",
            message: req.query.message || ""
        });

    } catch (err) {
        console.error("❌ Error in /doccv route:", err.message);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
    }
});
// ✅ Approve request
app.post("/yesDoc/:id", async (req, res) => {
    try {
        const requestId = new ObjectId(req.params.id);
        const requestCollection = db.collection("request");

        // Update request status → Approved
        const updateResult = await requestCollection.updateOne(
            { _id: requestId },
            { $set: { status: "Approved", updatedAt: new Date(), turnAt: new Date() } }
        );

        if (updateResult.modifiedCount === 0) {
            return res.json({ success: false, message: "No request found or already approved." });
        }

        // Fetch request + resident info
        const request = await requestCollection.findOne({ _id: requestId });
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(request.requestBy) });
        const familyHead = resident?.familyHeadId
            ? await db.collection("resident").findOne({ _id: new ObjectId(resident.familyHeadId) })
            : null;

        let emailRecipient = resident?.email || familyHead?.email || null;
        if (!emailRecipient) return res.json({ success: true, message: "Request approved, no email sent." });

        let emailHTML = `
            <p>Your request has been <strong>Approved</strong>.</p>
            <p>Request Reference: ${request._id}</p>
            <p>Thank you for using our system.</p>
        `;

        if (resident?.email !== emailRecipient) {
            emailHTML = `<p>The request for ${resident?.firstName || "your household member"} has been approved.</p>` + emailHTML;
        }

        await transporter.sendMail({
            from: '"Barangay San Andres" <johnniebre1995@gmail.com>',
            to: emailRecipient,
            subject: "Request Status Update - Approved",
            html: emailHTML
        });

        console.log("✅ Approval email sent:", emailRecipient);

        res.json({ success: true, message: "Request approved!", requestStatus: "Approved" });

    } catch (error) {
        console.error("Error in yesDoc:", error);
        res.status(500).json({ success: false, message: "Error approving request." });
    }
});


// ✅ Verify request
app.post("/verDoc/:id", async (req, res) => {
    try {
        const requestId = new ObjectId(req.params.id);
        const requestCollection = db.collection("request");

        const updateResult = await requestCollection.updateOne(
            { _id: requestId },
            { $set: { status: "Verified", updatedAt: new Date(), turnAt: new Date() } }
        );

        if (updateResult.modifiedCount === 0) {
            return res.json({ success: false, message: "No request found or already verified." });
        }

        const request = await requestCollection.findOne({ _id: requestId });
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(request.requestBy) });
        const familyHead = resident?.familyHeadId
            ? await db.collection("resident").findOne({ _id: new ObjectId(resident.familyHeadId) })
            : null;

        let emailRecipient = resident?.email || familyHead?.email || null;
        if (!emailRecipient) return res.json({ success: true, message: "Request verified, no email sent." });

        let emailHTML = `
            <p>Your request has been <strong>Verified</strong>.</p>
            <p>Request Reference: ${request._id}</p>
            <p>Thank you for using our system.</p>
        `;

        if (resident?.email !== emailRecipient) {
            emailHTML = `<p>The request for ${resident?.firstName || "your household member"} has been verified.</p>` + emailHTML;
        }

        await transporter.sendMail({
            from: '"Barangay San Andres" <johnniebre1995@gmail.com>',
            to: emailRecipient,
            subject: "Request Status Update - Verified",
            html: emailHTML
        });

        console.log("✅ Verification email sent:", emailRecipient);

        res.json({ success: true, message: "Request verified!", requestStatus: "Verified" });

    } catch (error) {
        console.error("Error in verDoc:", error);
        res.status(500).json({ success: false, message: "Error verifying request." });
    }
});


// ✅ Decline request
app.post("/noDoc/:id", async (req, res) => {
    try {
        const requestId = new ObjectId(req.params.id);
        const requestCollection = db.collection("request");
        const { notes } = req.body;

        const updateResult = await requestCollection.updateOne(
            { _id: requestId },
            { $set: { status: "Declined", notes: notes || "No notes provided.", updatedAt: new Date(), turnAt: new Date() } }
        );

        if (updateResult.modifiedCount === 0) {
            return res.json({ success: false, message: "No request found or already declined." });
        }

        const request = await requestCollection.findOne({ _id: requestId });
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(request.requestBy) });
        const familyHead = resident?.familyHeadId
            ? await db.collection("resident").findOne({ _id: new ObjectId(resident.familyHeadId) })
            : null;

        let emailRecipient = resident?.email || familyHead?.email || null;
        if (!emailRecipient) return res.json({ success: true, message: "Request declined, no email sent." });

        let emailHTML = `
            <p>Your request has been <strong>Declined</strong>.</p>
            <p>Reason: <strong>${notes || "No specific remarks."}</strong></p>
            <p>Request Reference: ${request._id}</p>
        `;

        if (resident?.email !== emailRecipient) {
            emailHTML = `<p>The request for ${resident?.firstName || "your household member"} has been declined.</p>` + emailHTML;
        }

        await transporter.sendMail({
            from: '"Barangay San Andres" <johnniebre1995@gmail.com>',
            to: emailRecipient,
            subject: "Request Status Update - Declined",
            html: emailHTML
        });

        console.log("❌ Decline email sent:", emailRecipient);

        res.json({ success: true, message: "Request declined!", requestStatus: "Declined" });

    } catch (error) {
        console.error("Error in noDoc:", error);
        res.status(500).json({ success: false, message: "Error declining request." });
    }
});


app.post("/release/:id", async (req, res) => {
    try {
        const requestId = new ObjectId(req.params.id);
        const requestCollection = db.collection("request");

        // Update request status
        const updateRequest = await requestCollection.updateOne(
            { _id: requestId },
            {
                $set: {
                    status: "Released",
                    updatedAt: new Date(),
                    successAt: new Date()
                }
            }
        );

        if (updateRequest.modifiedCount === 0) {
            return res.json({ success: false, message: "No request found or already updated." });
        }

        // Find request and resident details
        const request = await requestCollection.findOne({ _id: requestId });
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(request.requestBy) });

        let message = "The document has been released!";
        
        res.json({ success: true, message });

        if (resident?.email) {
            const mailOptions = {
                from: 'johnniebre1995@gmail.com',
                to: resident.email,
                subject: "Your Document has been released",
                html: `
                    <p>Dear <strong>${resident.firstName} ${resident.lastName}</strong>,</p>
                    <p>Your requested document has been <strong>released!</strong>.</p>
                    <p>Thank you.</p>
                `
            };

            try {
                await transporter.sendMail(mailOptions);
                console.log(`Email sent to ${resident.email}`);
                message += " Email notification sent.";
            } catch (emailError) {
                console.error("Error sending email:", emailError);
                message += " However, the email notification could not be sent.";
            }
        }


    } catch (error) {
        console.error("Error updating request status:", error);
        res.json({ success: false, message: "Error updating request status." });
    }
});


app.post("/cancel/:id", async (req, res) => {
    try {
        const requestId = new ObjectId(req.params.id);
        const requestCollection = db.collection("request");

        // Update request status
        const updateRequest = await requestCollection.updateOne(
            { _id: requestId },
            {
                $set: {
                    status: "Cancelled",
                    cancelAt: new Date(),
                    updatedAt: new Date()
                }
            }
        );

        if (updateRequest.modifiedCount === 0) {
            return res.json({ success: false, message: "No request found or already updated." });
        }

        // Find request and resident details
        const request = await requestCollection.findOne({ _id: requestId });
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(request.requestBy) });

        let message = "The document has been cancelled!";
        
        res.json({ success: true, message });

        if (resident?.email) {
            const mailOptions = {
                from: 'johnniebre1995@gmail.com',
                to: resident.email,
                subject: "Request Cancelled",
                html: `
                    <p>Dear <strong>${resident.firstName} ${resident.lastName}</strong>,</p>
                    <p>You have successfully<strong>cancelled</strong> your request.</p>
                `
            };

            try {
                await transporter.sendMail(mailOptions);
                console.log(`Email sent to ${resident.email}`);
                message += " Email notification sent.";
            } catch (emailError) {
                console.error("Error sending email:", emailError);
                message += " However, the email notification could not be sent.";
            }
        }


    } catch (error) {
        console.error("Error updating request status:", error);
        res.json({ success: false, message: "Error updating request status." });
    }
});


app.get("/srvPrint/:id", isLogin, async (req, res) => {
    try {
        const residentId = req.params.id; // Get the resident's _id from the URL

        // Fetch the resident data from the database
        const resident = await db.collection("resident").findOne({ _id: new ObjectId(residentId) });

        if (!resident) {
            return res.status(404).send('<script>alert("Resident not found!"); window.location="/rsd";</script>');
        }

        // Calculate Age Function
        const calculateAge = (bDay, bMonth, bYear) => {
            const months = {
                January: 1,
                February: 2,
                March: 3,
                April: 4,
                May: 5,
                June: 6,
                July: 7,
                August: 8,
                September: 9,
                October: 10,
                November: 11,
                December: 12
            };

            // Ensure we are using the correct date format
            const month = months[bMonth];
            if (!month) return 0;

            const birthDateString = `${bYear}-${String(month).padStart(2, '0')}-${String(bDay).padStart(2, '0')}`;
            const birthDate = new Date(birthDateString);

            if (isNaN(birthDate)) return 0;

            const ageDifMs = Date.now() - birthDate.getTime();
            const ageDate = new Date(ageDifMs);
            return Math.abs(ageDate.getUTCFullYear() - 1970);  // Calculate age
        };

        // Render the details page with the resident's data and calculated age
        res.render("srvPrint", {
            layout: "layout",
            title: "Resident Details",
            activePage: "srv",
            resident: resident,
            calculateAge: calculateAge,  // Passing the function to the template
        });
    } catch (err) {
        console.error("Error fetching resident details:", err.message);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/rsd";</script>');
    }
});

const moment = require("moment");
const { error } = require("console");

 
app.get("/exportPDF", isLogin, async (req, res) => {
    try {
        // Fetch data from MongoDB
        const residents = await db.collection("resident").find({ archive: { $in: ["0", 0] } }).toArray();
        const businesses = await db.collection("business").countDocuments({ archive: { $in: ["0", 0] } });
        const pendingCount = await db.collection("request").countDocuments({ status: { $in: ["Pending", "Processing"] } });

        const totalPopulation = residents.length;
        const maleCount = residents.filter(r => r.gender?.toLowerCase() === "male").length;
        const femaleCount = residents.filter(r => r.gender?.toLowerCase() === "female").length;
        const uniqueHouseholds = new Set(residents.map(r => `${r.houseNo || ""}-${r.purok || ""}`)).size;
        const totalFamilies = residents.filter(r => r.role?.toLowerCase() === "head").length;
        const skVoters = residents.filter(r => calculateAge(r.bMonth, r.bDay, r.bYear) >= 15 && calculateAge(r.bMonth, r.bDay, r.bYear) <= 30 && r.precinct).length;
        const registeredVoters = residents.filter(r => r.precinct).length;

        // Age Distribution
        const ageGroups = {
            "0-5 Months": 0,
            "6-11 Months": 0,
            "1-5 Years Old": 0,
            "6-12 Years Old": 0,
            "13-17 Years Old": 0,
            "18-59 Years Old": 0,
            "15-30 (SK Voters)": 0,
            "59 & Above (Senior Citizen)": 0
        };

        residents.forEach(r => {
            const age = calculateAge(r.bMonth, r.bDay, r.bYear);
            if (age < 1) {
                const monthsOld = moment().diff(`${r.bYear}-${r.bMonth}-${r.bDay}`, "months");
                if (monthsOld <= 5) ageGroups["0-5 Months"]++;
                else ageGroups["6-11 Months"]++;
            } else if (age >= 1 && age <= 5) ageGroups["1-5 Years Old"]++;
            else if (age >= 6 && age <= 12) ageGroups["6-12 Years Old"]++;
            else if (age >= 13 && age <= 17) ageGroups["13-17 Years Old"]++;
            else if (age >= 18 && age <= 59) ageGroups["18-59 Years Old"]++;
            if (age >= 15 && age <= 30) ageGroups["15-30 (SK Voters)"]++;
            if (age >= 59) ageGroups["59 & Above (Senior Citizen)"]++;
        });

        // Calculate Percentages
        const calcPercentage = (count) => (totalPopulation > 0 ? ((count / totalPopulation) * 100).toFixed(2) : "0.00");

        // Create PDF Document
        const doc = new PDFDocument({ margin: 50 });
        const fileName = `Dashboard_Report_${Date.now()}.pdf`;
        const filePath = path.join(__dirname, "public", "reports", fileName);

        // Ensure reports directory exists
        if (!fs.existsSync(path.join(__dirname, "public", "reports"))) {
            fs.mkdirSync(path.join(__dirname, "public", "reports"), { recursive: true });
        }

        const writeStream = fs.createWriteStream(filePath);
        doc.pipe(writeStream);

        // Add Title
        doc.fontSize(20).fillColor("#1F4E79").text("Dashboard Report", { align: "center" }).moveDown(1);

        // Table Styling
        let x = 50;
        let y = 120;
        const rowHeight = 25;
        const colWidths = [200, 100, 100];

        // Draw table headers with background color
        doc.fillColor("#FFFFFF").fontSize(12).text("Category", x + 10, y, { bold: true });
        doc.text("Count", x + colWidths[0] + 10, y, { bold: true });
        doc.text("Percentage", x + colWidths[0] + colWidths[1] + 10, y, { bold: true });

        doc.rect(x, y - 5, colWidths[0] + colWidths[1] + colWidths[2], rowHeight)
            .fill("#9bf6c6ff")
            .stroke();

        doc.fillColor("#000000");

        y += rowHeight;

        // General Statistics
        addTableRow(doc, x, y, "Total Population", totalPopulation, "100%");
        addTableRow(doc, x, y += rowHeight, "Male Residents", maleCount, `${calcPercentage(maleCount)}%`);
        addTableRow(doc, x, y += rowHeight, "Female Residents", femaleCount, `${calcPercentage(femaleCount)}%`);
        addTableRow(doc, x, y += rowHeight, "Total Households", uniqueHouseholds, `${calcPercentage(uniqueHouseholds)}%`);
        addTableRow(doc, x, y += rowHeight, "Total Families", totalFamilies, `${calcPercentage(totalFamilies)}%`);
        addTableRow(doc, x, y += rowHeight, "Total Businesses", businesses, `${calcPercentage(businesses)}%`);
        addTableRow(doc, x, y += rowHeight, "Registered Voters", registeredVoters, `${calcPercentage(registeredVoters)}%`);
        addTableRow(doc, x, y += rowHeight, "SK Voters", skVoters, `${calcPercentage(skVoters)}%`);
        y += rowHeight * 2; // Space before Age Distribution
doc.fontSize(14).fillColor("#9bf6c6ff").text("Age Distribution", x, y).moveDown(1);
doc.fillColor("#000000").fontSize(12);

Object.keys(ageGroups).forEach((group) => {
    addTableRow(doc, x, y += rowHeight, group, ageGroups[group], `${calcPercentage(ageGroups[group])}%`);
});

        

        // Finalize PDF
        doc.end();

        writeStream.on("finish", () => {
            res.download(filePath, fileName, (err) => {
                if (err) console.error("❌ Error downloading PDF:", err);
                fs.unlinkSync(filePath); // Delete file after download
            });
        });

    } catch (err) {
        console.error("❌ Error generating PDF:", err);
        res.status(500).send('<script>alert("Failed to generate PDF!"); window.location="/dsb";</script>');
    }
});

// Function to add styled rows to the PDF table
function addTableRow(doc, x, y, label, count, percentage) {
    const rowHeight = 25;
    const colWidths = [200, 100, 100];

    doc.rect(x, y, colWidths[0] + colWidths[1] + colWidths[2], rowHeight)
        .stroke();

    doc.fillColor("#000000").fontSize(12);
    doc.text(label, x + 10, y + 5);
    doc.text(count.toString(), x + colWidths[0] + 10, y + 5);
    doc.text(percentage, x + colWidths[0] + colWidths[1] + 10, y + 5);
}

function calculateAge(bMonth, bDay, bYear) {
    if (!bMonth || !bDay || !bYear) return 0;

    // Convert to integers if they come in as strings
    const year = parseInt(bYear, 10);
    const monthIndex = parseInt(bMonth, 10) - 1; // 0-based for moment
    const day = parseInt(bDay, 10);

    const birthDate = moment([year, monthIndex, day]);
    if (!birthDate.isValid()) return 0;

    return moment().diff(birthDate, 'years');
}

app.get("/getRequestCount", async (req, res) => {
    try {
        const requestCount = await db.collection("request").countDocuments({});
        res.json({ count: requestCount });
    } catch (err) {
        console.error("Error fetching request count:", err);
        res.status(500).json({ count: 0 });
    }
});

app.get("/getPendingCount", async (req, res) => {
    try {
        const pendingCount = await db.collection("request").countDocuments({ status: "Pending" });
        res.json({ count: pendingCount });
    } catch (err) {
        console.error("Error fetching pending count:", err);
        res.status(500).json({ count: 0 });
    }
});

const myReqView = async (req, res) => {
    try {
        if (!req.user) {
            console.log("User is not logged in.");
            return res.redirect("/");
        }

        const requestId = req.params.id;
        console.log("🔎 Request ID:", requestId);

        if (!ObjectId.isValid(requestId)) {
            console.log("❌ Invalid request ID format.");
            return res.status(400).send("Invalid request ID.");
        }

        const objectIdRequestId = new ObjectId(requestId);

        // Ensure sessionUserId is ObjectId
        let sessionUserId = req.user._id;
        if (typeof sessionUserId === "string" && ObjectId.isValid(sessionUserId)) {
            sessionUserId = new ObjectId(sessionUserId);
        }

        // Fetch request (now contains document info itself)
        const request = await db.collection("request").findOne({
            _id: objectIdRequestId,
            requestBy: sessionUserId,
            archive: { $in: [0, "0"] }
        });

        if (!request) {
            return res.status(404).send("Request not found.");
        }

        // Resident who submitted (requestBy)
        let resident = null;
        if (request.requestBy) {
            resident = await db.collection("resident").findOne({
                _id: new ObjectId(request.requestBy)
            });
        }

        // Resolve requestFor (who the document is for)
        let requestForResident = null;
        if (request.requestFor && request.requestFor.toString() !== sessionUserId.toString()) {
            if (ObjectId.isValid(request.requestFor)) {
                requestForResident = await db.collection("resident").findOne({
                    _id: new ObjectId(request.requestFor)
                });
            }
        }

        // Attach requestFor info
        if (request.requestFor) {
            if (request.requestFor.toString() === sessionUserId.toString()) {
                request.isMyself = true;
                request.residentInfo = resident; // own info
            } else if (requestForResident) {
                request.residentInfo = requestForResident;
            }
        }

        res.render("reqView", { request, resident });

    } catch (err) {
        console.error("⚠️ Error in myReqView:", err);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
    }
};


app.get('/authLetter', (req, res) => {
    const filePath = path.join(__dirname, 'public', 'files', 'au.pdf');
    res.download(filePath, 'Authorization_Letter.pdf', (err) => {
        if (err) {
            console.error('Error downloading file:', err);
            return res.status(500).send('Error downloading file');
        }
        res.end(); // Explicitly end the response
    });
});
app.get('/downloadAuthLetter', (req, res) => {
    res.send(`
        <html>
        <head>
            <script>
                window.onload = function() {
                    // Trigger the download
                    const downloadLink = document.createElement('a');
                    downloadLink.href = '/authLetter';
                    downloadLink.download = 'Authorization_Letter.pdf';
                    document.body.appendChild(downloadLink);
                    downloadLink.click();
                    document.body.removeChild(downloadLink);

                    // Redirect back after a short delay
                    setTimeout(() => {
                        window.history.back(); // Go back to the previous page
                    }, 1000);
                };
            </script>
        </head>
        <body>
            <p>Downloading Authorization Letter...</p>
        </body>
        </html>
    `);
});

app.get('/reqView/:id', isLogin, myReqView);
app.get('/acc', isRsd, (req, res) => { res.render("acc" , { layout: "layout", title: "Access", activePage: "rsd" })});

app.get("/export-residents", isLogin, (req, res) => {
    res.render("downloading", { title: "", layout: "layout", activePage: ""});
});


app.get("/download-residents", isLogin, async (req, res) => {
    try {
        const residents = await db.collection("resident").aggregate([
            {
                $lookup: {
                    from: "household",
                    localField: "householdId",
                    foreignField: "_id",
                    as: "householdInfo"
                }
            },
            {
                $unwind: {
                    path: "$householdInfo",
                    preserveNullAndEmptyArrays: true
                }
            }
        ]).toArray();

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet("Residents");

// 🟢 Add a title row
worksheet.mergeCells("A1:T1"); // adjust range according to last column
worksheet.getCell("A1").value = "Barangay San Andres - Residents List";
worksheet.getCell("A1").font = { size: 16, bold: true };
worksheet.getCell("A1").alignment = { vertical: "middle", horizontal: "center" };

// 🟢 Add a subtitle row
worksheet.mergeCells("A2:T2");
worksheet.getCell("A2").value = `Generated on: ${new Date().toLocaleDateString()}`;
worksheet.getCell("A2").font = { size: 12, italic: true };
worksheet.getCell("A2").alignment = { vertical: "middle", horizontal: "center" };

// 🟢 Leave one empty row
worksheet.addRow([]);

// 🟢 Define columns without auto header row
worksheet.columns = [
    { key: "completeName", width: 25 },
    { key: "address", width: 25 },
    { key: "birthday", width: 20 },
    { key: "birthPlace", width: 20 },
    { key: "phone", width: 15 },
    { key: "email", width: 25 },
    { key: "gender", width: 10 },
    { key: "civilStatus", width: 15 },
    { key: "precinct", width: 15 },
    { key: "role", width: 15 },
    { key: "priority", width: 15 },
    { key: "priorityType", width: 20 },
    { key: "pregnant", width: 12 },
    { key: "soloParent", width: 15 },
    { key: "pwd", width: 10 },
    { key: "pwdType", width: 15 },
    { key: "employmentStatus", width: 20 },
    { key: "work", width: 20 },
    { key: "monthlyIncome", width: 15 },
    { key: "position", width: 20 }
];

// 🟢 Manually add header row
worksheet.addRow([
    "Complete Name", "Address", "Birthday", "Birth Place", "Phone", "Email",
    "Gender", "Civil Status", "Precinct", "Role", "Priority", "Priority Type",
    "Pregnant", "Solo Parent", "PWD", "PWD Type", "Employment Status", "Work",
    "Monthly Income", "Position"
]);

// Style header row
const headerRow = worksheet.lastRow;
headerRow.font = { bold: true };
headerRow.alignment = { vertical: "center", horizontal: "center" };
headerRow.eachCell(cell => {
    cell.fill = {
        type: "pattern",
        pattern: "solid",
        fgColor: { argb: "FFD9D9D9" } // light gray background
    };
    cell.border = {
        top: { style: "thin" },
        left: { style: "thin" },
        bottom: { style: "thin" },
        right: { style: "thin" }
    };
});
        const convertYesNo = (value) => {
            if (value === "on") return "Yes";
            if (value === "off") return "No";
            return value ?? "";
        };

        const formattedData = residents.map(resident => {
            const household = resident.householdInfo || {};
            const houseNo = household.houseNo || "";
            const purok = household.purok || "";

            let birthday = "";
            if (resident.bMonth && resident.bDay && resident.bYear) {
                const month =
                    isNaN(resident.bMonth) && typeof resident.bMonth === "string"
                        ? resident.bMonth
                        : new Date(0, parseInt(resident.bMonth) - 1).toLocaleString("en-US", { month: "long" });

                birthday = `${month} ${resident.bDay}, ${resident.bYear}`;
            }

            return {
                completeName: `${resident.firstName} ${resident.middleName || ""} ${resident.lastName} ${resident.extName || ""}`.trim(),
                address: `${houseNo}, Purok ${purok}`,
                birthday,
                birthPlace: resident.birthPlace || "",
                phone: resident.phone || "",
                email: resident.email || "",
                gender: resident.gender || "",
                civilStatus: resident.civilStatus || "",
                precinct: resident.precinct || "",
                role: resident.role || "",
                priority: resident.priority || "",
                priorityType: resident.priorityType || "",
                pregnant: convertYesNo(resident.pregnant),
                soloParent: convertYesNo(resident.soloParent),
                pwd: convertYesNo(resident.pwd),
                pwdType: resident.pwdType || "",
                employmentStatus: resident.employmentStatus || "",
                work: resident.work || "",
                monthlyIncome: resident.monthlyIncome || "",
                position: resident.position || ""
            };
        });

        worksheet.addRows(formattedData);

        const buffer = await workbook.xlsx.writeBuffer();

        res.setHeader("Content-Disposition", "attachment; filename=residents.xlsx");
        res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");

        res.send(Buffer.from(buffer));
    } catch (error) {
        console.error("❌ Error exporting residents:", error);
        res.status(500).json({ message: "Error exporting residents data." });
    }
});


app.get("/export-residents2", isLogin, (req, res) => {
    res.render("downloading2", { title: "", layout: "layout", activePage: ""} );
});

app.get("/download-residents2", isLogin, async (req, res) => {
    try {
        const residents = await db.collection("resident")
    .find({ archive: { $in: [0, "0"] } })
    .toArray();

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet("Residents");

// 🟢 Add a title row
worksheet.mergeCells("A1:T1"); // adjust range according to last column
worksheet.getCell("A1").value = "Barangay San Andres - Residents List";
worksheet.getCell("A1").font = { size: 16, bold: true };
worksheet.getCell("A1").alignment = { vertical: "middle", horizontal: "center" };

// 🟢 Add a subtitle row
worksheet.mergeCells("A2:T2");
worksheet.getCell("A2").value = `Generated on: ${new Date().toLocaleDateString()}`;
worksheet.getCell("A2").font = { size: 12, italic: true };
worksheet.getCell("A2").alignment = { vertical: "middle", horizontal: "center" };

// 🟢 Leave one empty row
worksheet.addRow([]);

// 🟢 Define columns without auto header row
worksheet.columns = [
    { key: "completeName", width: 25 },
    { key: "address", width: 25 },
    { key: "birthday", width: 20 },
    { key: "birthPlace", width: 20 },
    { key: "phone", width: 15 },
    { key: "email", width: 25 },
    { key: "gender", width: 10 },
    { key: "civilStatus", width: 15 },
    { key: "precinct", width: 15 },
    { key: "role", width: 15 },
    { key: "priority", width: 15 },
    { key: "priorityType", width: 20 },
    { key: "pregnant", width: 12 },
    { key: "soloParent", width: 15 },
    { key: "pwd", width: 10 },
    { key: "pwdType", width: 15 },
    { key: "employmentStatus", width: 20 },
    { key: "work", width: 20 },
    { key: "monthlyIncome", width: 15 },
    { key: "position", width: 20 }
];

// 🟢 Manually add header row
worksheet.addRow([
    "Complete Name", "Address", "Birthday", "Birth Place", "Phone", "Email",
    "Gender", "Civil Status", "Precinct", "Role", "Priority", "Priority Type",
    "Pregnant", "Solo Parent", "PWD", "PWD Type", "Employment Status", "Work",
    "Monthly Income", "Position"
]);

// Style header row
const headerRow = worksheet.lastRow;
headerRow.font = { bold: true };
headerRow.alignment = { vertical: "center", horizontal: "center" };
headerRow.eachCell(cell => {
    cell.fill = {
        type: "pattern",
        pattern: "solid",
        fgColor: { argb: "FFD9D9D9" } // light gray background
    };
    cell.border = {
        top: { style: "thin" },
        left: { style: "thin" },
        bottom: { style: "thin" },
        right: { style: "thin" }
    };
});
        const monthNames = [
            "", "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December"
        ];

        const formattedData = [];

        for (const resident of residents) {
            let houseNo = "";
            let purok = "";

            if (resident.householdId) {
                const household = await db.collection("household").findOne({ _id: new ObjectId(resident.householdId) });
                if (household) {
                    houseNo = household.houseNo || "";
                    purok = household.purok || "";
                }
            }

            const monthIndex = parseInt(resident.bMonth); // Convert to number
            const monthName = !isNaN(monthIndex) && monthIndex >= 1 && monthIndex <= 12 ? monthNames[monthIndex] : "";
            const birthday = `${monthName} ${resident.bDay || ""}, ${resident.bYear || ""}`;

            const formatSwitch = (val) => val === "on" ? "Yes" : val === "off" ? "No" : "";

            formattedData.push({
                completeName: `${resident.firstName} ${resident.middleName || ""} ${resident.lastName} ${resident.extName || ""}`.trim(),
                address: `${houseNo}, Purok ${purok}`,
                birthday,
                birthPlace: resident.birthPlace || "",
                phone: resident.phone || "",
                email: resident.email || "",
                gender: resident.gender || "",
                civilStatus: resident.civilStatus || "",
                precinct: resident.precinct || "",
                role: resident.role || "",
                pwd: formatSwitch(resident.pwd),
                pwdType: resident.pwdType || "",
                pregnant: formatSwitch(resident.pregnant),
                soloParent: formatSwitch(resident.soloParent),
                priorityType: resident.priorityType || "",
                employmentStatus: resident.employmentStatus || "",
                work: resident.work || "",
                monthlyIncome: resident.monthlyIncome || "",
                position: resident.position || ""
            });
        }

        worksheet.addRows(formattedData);

        const buffer = await workbook.xlsx.writeBuffer();

        res.setHeader("Content-Disposition", "attachment; filename=residents.xlsx");
        res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        res.send(Buffer.from(buffer));

    } catch (error) {
        console.error("❌ Error exporting residents:", error);
        res.status(500).json({ message: "Error exporting residents data." });
    }
});

app.get("/export-business", isLogin, (req, res) => {
    res.render("exporting", { title: "", layout: "layout", activePage: ""} );
});


app.get("/download-business", async (req, res) => {
    try {
        const businesses = await db.collection("business")
    .find({ archive: { $in: [0, "0"] } })
    .toArray();

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet("Businesses");

        // Define the columns
        worksheet.columns = [
            { header: "Name of Business", key: "businessName", width: 25 },
            { header: "Owner", key: "ownerName", width: 25 },
            { header: "Type", key: "businessType", width: 20 },
            { header: "Contact", key: "contactNumber", width: 15 },
            { header: "Address", key: "address", width: 30 }
        ];

        // Format data
        const formattedData = businesses.map(business => ({
            businessName: business.businessName || "No Record",
            ownerName: business.ownerName || "No Record",
            businessType: business.businessType || "No Record",
            contactNumber: business.contactNumber || "No Record",
            address: `${business.houseNo || "No Record"}, ${business.purok || "No Record"}`
        }));

        worksheet.addRows(formattedData);

        // Generate the file buffer
        const buffer = await workbook.xlsx.writeBuffer();

        // Set headers for file download
        res.setHeader("Content-Disposition", "attachment; filename=businesses.xlsx");
        res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");

        // Send the buffer to the client
        res.send(Buffer.from(buffer));

    } catch (error) {
        console.error("❌ Error exporting businesses:", error);
        res.status(500).json({ message: "Error exporting business data." });
    }
});


app.post('/add-case', async (req, res) => {
    try {
        console.log("Received Data:", req.body);
        const { type, complainants, complainees } = req.body;

        if (!type) {
            return res.status(400).json({ error: "Type of case is required." });
        }

        // Generate Case Number
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');

        const count = await db.collection('cases').countDocuments({
            caseNo: { $regex: `^${year}-${month}` }
        });

        const sequence = String(count + 1).padStart(4, '0');
        const caseNo = `${year}-${month}${sequence}`;
        console.log("Generated Case No:", caseNo);

        // Insert new case
        const caseData = {
            caseNo,
            type,
            status: "Pending",
            createdAt: now
        };

        const caseResult = await db.collection('cases').insertOne(caseData);
        const caseId = caseResult.insertedId;
        console.log("Case inserted with ID:", caseId);

        // Format complainants & complainees
        const formatPersons = (persons, role) => {
            if (!persons) return [];
            try {
                const parsedPersons = Array.isArray(persons)
                    ? persons.map(p => (typeof p === 'string' ? JSON.parse(p) : p))
                    : [typeof persons === 'string' ? JSON.parse(persons) : persons];

                return parsedPersons.map(person => ({
                    caseId,
                    name: person.name.trim(),
                    address: person.address ? person.address.trim() : "No Address",
                    phone: person.phone ? person.phone.trim() : "No Phone"
                }));
            } catch (error) {
                console.error(`Error parsing ${role}:`, error);
                return [];
            }
        };

        // Insert complainants
        const complainantList = formatPersons(complainants, "Complainants");
        if (complainantList.length > 0) {
            await db.collection('complainants').insertMany(complainantList);
            console.log(`Inserted ${complainantList.length} complainants.`);
        }

        // Insert complainees
        const complaineeList = formatPersons(complainees, "Complainees");
        if (complaineeList.length > 0) {
            await db.collection('complainees').insertMany(complaineeList);
            console.log(`Inserted ${complaineeList.length} complainees.`);
        }

        // Redirect with success message as a query parameter
        return res.redirect(`/viewCmp/${caseId}?success=Case added successfully! Case No: ${caseNo}`);

    } catch (error) {
        console.error("Error inserting case:", error);
        res.redirect(`/viewCmp/error?error=An error occurred while adding the case.`);
    }
});

app.get("/blot", isLogin, isRsd, isHr, async (req, res) => {
    try {
        // Fetch all cases, ordered by createdAt (latest first)
        const cases = await db.collection("cases")
        .find({ archive: { $in: ["0", 0] } }) // Filters only archive: 0
        .sort({ createdAt: -1 })
        .toArray();

        // Extract resident IDs from cases (complainants and respondents)
        const residentIds = cases.flatMap(c => [...c.complainants, ...c.respondents])
            .filter(id => id) // Remove empty or undefined values
            .map(id => ObjectId.isValid(id) ? new ObjectId(id) : id);

        console.log("Resident IDs for lookup:", residentIds); // Debugging log

        // Fetch residents using `_id` (Check both ObjectId and String formats)
        const residentsData = await db.collection("resident").find({
            _id: { $in: residentIds }
        }).toArray();

        console.log("Residents found:", residentsData); // Debugging log

        // Map resident IDs to full names
        const residentsMap = {};
        residentsData.forEach(resident => {
            const residentIdStr = resident._id.toString(); // Convert `_id` to string
            residentsMap[residentIdStr] = `${resident.firstName} ${resident.middleName || ''} ${resident.lastName} ${resident.extName || ''}`.trim();
        });

        console.log("Residents Map:", residentsMap); // Debugging log

        // Organize complainants and respondents by caseId
        const complainantsByCase = {};
        const respondentsByCase = {};
        cases.forEach(c => {
            complainantsByCase[c._id] = c.complainants.map(id => residentsMap[id] || "Unknown");
            respondentsByCase[c._id] = c.respondents.map(id => residentsMap[id] || "Unknown");
        });

        console.log("Final Complainants by Case:", complainantsByCase); // Debugging log
        console.log("Final Respondents by Case:", respondentsByCase); // Debugging log

        // Fetch all schedules and group them by caseId
        const schedules = await db.collection("schedule").find().toArray();
        const schedulesByCase = {};
        schedules.forEach(s => {
            if (!schedulesByCase[s.caseId]) schedulesByCase[s.caseId] = [];
            schedulesByCase[s.caseId].push(s);
        });

        // Render the 'cmp' view with all data
        res.render("blot", { 
            layout: "layout", 
            title: "Complaints", 
            activePage: "blot",
            cases,
            complainantsByCase,
            respondentsByCase,
            schedulesByCase
        });
    } catch (error) {
        console.error("Error fetching cases:", error);
        res.status(500).send("An error occurred while retrieving cases.");
    }
});

app.get("/blotv/:id", isLogin, isRsd, isHr, async (req, res) => {
    try {
        const caseId = req.params.id;

        if (!ObjectId.isValid(caseId)) {
            return res.status(400).send("Invalid case ID");
        }

        // Fetch the case
        const caseItem = await db.collection("cases").findOne({ _id: new ObjectId(caseId) });
        if (!caseItem) {
            return res.status(404).send("Case not found");
        }

        // Collect complainant + respondent IDs
        const residentIds = [...(caseItem.complainants || []), ...(caseItem.respondents || [])]
            .filter(id => id)
            .map(id => ObjectId.isValid(id) ? new ObjectId(id) : id);

        // Fetch residents
        const residentsData = await db.collection("resident").find({
            _id: { $in: residentIds }
        }).toArray();

        // Map resident IDs to full names
        const residentsMap = {};
        residentsData.forEach(resident => {
            const residentIdStr = resident._id.toString();
            residentsMap[residentIdStr] = `${resident.firstName} ${resident.middleName || ''} ${resident.lastName} ${resident.extName || ''}`.trim();
        });

        // Map complainants and respondents for display
        const complainants = (caseItem.complainants || []).map(id => residentsMap[id] || "Unknown");
        const respondents = (caseItem.respondents || []).map(id => residentsMap[id] || "Unknown");

        // Fetch schedules for this case
        const schedules = await db.collection("schedule").find({ caseId: caseItem._id.toString() }).toArray();

        // Render case detail view
        res.render("blotv", {
            layout: "layout",
            title: "Case Details",
            activePage: "blot",
            caseItem,
            complainants,
            respondents,
            schedules
        });
    } catch (error) {
        console.error("Error fetching case details:", error);
        res.status(500).send("An error occurred while retrieving case details.");
    }
});

app.get("/editBlot/:id", isLogin, isRsd, isHr, async (req, res) => {
  try {
    const caseId = req.params.id;
    if (!ObjectId.isValid(caseId)) return res.status(400).send("Invalid case ID");

    const caseItem = await db.collection("cases").findOne({ _id: new ObjectId(caseId) });
    if (!caseItem) return res.status(404).send("Case not found");

    const residentIds = [...(caseItem.complainants || []), ...(caseItem.respondents || [])]
      .filter(Boolean)
      .map(id => ObjectId.isValid(id) ? new ObjectId(id) : id);

    const residentsCursor = await db.collection("resident").find({ _id: { $in: residentIds } });
    const residentsRaw = await residentsCursor.toArray();

    // Map to plain objects with string _id for client
    const residents = residentsRaw.map(r => ({
      _id: r._id.toString(),
      firstName: r.firstName || "",
      middleName: r.middleName || "",
      lastName: r.lastName || "",
      extName: r.extName || ""
    }));

    // Render the edit page and pass the caseItem and residents
    res.render("editBlot", {
    layout: "layout",
    title: "Edit Blotter",
    activePage: "blot",
    caseItem,
    residents,
    complainants: caseItem.complainants || [],
    respondents: caseItem.respondents || [],
    });
  } catch (error) {
    console.error("Error fetching case details:", error);
    res.status(500).send("An error occurred while retrieving case details.");
  }
});

app.get("/cmn", isLogin, isRsd, isHr, (req, res) => res.render("cmn", { layout: "layout", title: "Add Complaint", activePage: "blot" }));

app.get('/viewCmp/:id', isRsd, isLogin, async (req, res) => {
    try {
        const caseId = req.params.id;
        const error = req.query.error || ""; // ✅ Capture error message from query parameter
        console.log("Fetching case with ID:", caseId);

        // ✅ Validate caseId format
        if (!ObjectId.isValid(caseId)) {
            return res.redirect('/?error=Invalid case ID');
        }

        // ✅ Fetch case details
        const caseData = await db.collection('cases').findOne({ _id: new ObjectId(caseId) });
        if (!caseData) {
            return res.redirect('/?error=Case not found');
        }

        // ✅ Fetch complainants & complainees
        const [complainants, complainees] = await Promise.all([
            db.collection('complainants').find({ caseId: new ObjectId(caseId) }).toArray(),
            db.collection('complainees').find({ caseId: new ObjectId(caseId) }).toArray()
        ]);

        // ✅ Fetch schedules where caseId matches
        const schedules = await db.collection('schedule').find({ caseId: caseId }).toArray();
        console.log("Schedules Found:", schedules);

        // ✅ Extract unique resident IDs from schedules
        const residentIds = schedules.flatMap(schedule => 
            [schedule.chair, schedule.secretary, schedule.member].filter(id => id)
        ).map(id => new ObjectId(id));

        const uniqueResidentIds = [...new Set(residentIds)];
        console.log("Fetching residents with IDs:", uniqueResidentIds);

        // ✅ Fetch residents (Chair, Secretary, Member) based on IDs
        const residents = uniqueResidentIds.length > 0 
            ? await db.collection('resident').find({ _id: { $in: uniqueResidentIds } }).toArray()
            : [];

        // ✅ Attach resident details to schedules
        schedules.forEach(schedule => {
            schedule.chair = residents.find(res => res._id.toString() === schedule.chair) || { firstName: "N/A" };
            schedule.secretary = residents.find(res => res._id.toString() === schedule.secretary) || { firstName: "N/A" };
            schedule.member = residents.find(res => res._id.toString() === schedule.member) || { firstName: "N/A" };
        });

        // ✅ Render the page with the error message
        res.render('viewCmp', { 
            caseData, complainants, complainees, schedules, error,
            layout: "layout", title: "Add Complaint", activePage: "blot" 
        });

    } catch (err) {
        console.error("Error fetching case:", err);
        res.redirect('/?error=An error occurred while fetching the case');
    }
});

app.post("/myUpdate", requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId; // logged-in user's ID

        if (!ObjectId.isValid(userId)) {
            return res.status(400).send("Invalid user ID");
        }

        // Destructure all fields from req.body, excluding checkboxes
        const {
            firstName, middleName, lastName, extName,
            houseNo, purok, bMonth, bDay, bYear, birthPlace,
            gender, civilStatus, precinct, education, nationality,
            religion, phone, email, pwdType, employmentStatus, work, position
        } = req.body;

        // Handle checkboxes: "On" if checked, "No" if unchecked
        const soloParent = req.body.soloParent ? "on" : "no";
        const pregnant   = req.body.pregnant ? "on" : "no";
        const pwd        = req.body.pwd ? "on" : "no";

        // Build update object
        const updateData = {
            firstName,
            middleName,
            lastName,
            extName,
            houseNo,
            purok,
            bMonth: parseInt(bMonth),
            bDay: parseInt(bDay),
            bYear: parseInt(bYear),
            birthPlace,
            gender,
            civilStatus,
            precinct,
            education,
            nationality,
            religion,
            phone,
            email,
            soloParent,           // "On" / "No"
            pregnant,             // "On" / "No"
            pwd,                  // "On" / "No"
            pwdType: pwd === "on" ? pwdType : "", // only keep if PWD is checked
            employmentStatus,
            work,
            position
        };

        // Update in MongoDB
        await db.collection("resident").updateOne(
            { _id: new ObjectId(userId) },
            { $set: updateData }
        );

        res.redirect("/prf"); // go back to profile page
    } catch (err) {
        console.error("❌ Error updating user:", err);
        res.status(500).send("Error updating user information");
    }
});


app.post("/myPassword", requireAuth, async (req, res) => {
    try {
        const { password } = req.body;
        const userId = req.session.userId; // Get the logged-in user's ID from session

        if (!ObjectId.isValid(userId)) {
            return res.status(400).send("Invalid user ID");
        }

        // Update user in MongoDB
        await db.collection("resident").updateOne(
            { _id: new ObjectId(userId) },
            { $set: { password } }
        );

        res.redirect("/prf"); // Redirect to the profile page after update
    } catch (err) {
        console.error("❌ Error updating user:", err);
        res.status(500).send("Error updating user information");
    }
});

app.post("/myPasswordRST", requireAuth, async (req, res) => {
    try {
        const { password } = req.body;
        const userId = req.session.userId; // Get the logged-in user's ID from session

        if (!ObjectId.isValid(userId)) {
            return res.status(400).send("Invalid user ID");
        }

        // Update user in MongoDB: set new password & reset = 0
        await db.collection("resident").updateOne(
            { _id: new ObjectId(userId) },
            { $set: { password, reset: 0 } }
        );

        res.redirect("/prf"); // Redirect to the profile page after update
    } catch (err) {
        console.error("❌ Error updating user:", err);
        res.status(500).send("Error updating user information");
    }
});


app.get("/api/success-per-month", async (req, res) => {
    try {
        const monthlySuccess = new Array(12).fill(0);
        let totalRequests = 0;

        const successDocuments = await db.collection("request").find({
            status: { $in: ["Success", "Approved", "Processed"] },
            archive: { $in: [0, "0"] }
        }).toArray();

        successDocuments.forEach(doc => {
            if (doc.updatedAt) {
                let monthIndex = new Date(doc.updatedAt).getMonth();
                if (!isNaN(monthIndex) && monthIndex >= 0 && monthIndex < 12) {
                    monthlySuccess[monthIndex]++;
                    totalRequests++; // Increment total count
                }
            }
        });

        res.json({ monthlySuccess, totalRequests });
    } catch (error) {
        console.error("Error fetching success documents:", error);
        res.json({ monthlySuccess: new Array(12).fill(0), totalRequests: 0 });
    }
});

app.get("/api/age-distribution", async (req, res) => {
    try {
        const ageGroups = {
            "0-5 Months": 0,
            "6-11 Months": 0,
            "1-5 Years Old": 0,
            "6-12 Years Old": 0,
            "13-17 Years Old": 0,
            "18-59 Years Old": 0,
            "60 and above": 0
        };
        let totalResidents = 0;

        const residents = await db.collection("resident").find({ archive: { $in: [0, "0"] } }).toArray();
        
        const currentDate = new Date();
        const currentYear = currentDate.getFullYear();
        const currentMonth = currentDate.getMonth() + 1; // Month is 0-indexed, so we add 1
        const currentDay = currentDate.getDate();

        residents.forEach(resident => {
            // Exclude residents with future birth dates
            if (resident.bYear && resident.bMonth && resident.bDay) {
                const birthYear = parseInt(resident.bYear);
                const birthMonth = new Date(Date.parse(resident.bMonth + " 1, 2000")).getMonth() + 1; // Convert month name to number
                const birthDay = parseInt(resident.bDay);

                const birthDate = new Date(birthYear, birthMonth - 1, birthDay);

                // If the birth date is in the future, skip the resident
                if (birthDate > currentDate) {
                    console.log(`Skipping future birth date for Resident: ${resident._id}`);
                    return;
                }

                let age = currentYear - birthYear;
                let monthDiff = currentMonth - birthMonth;
                let dayDiff = currentDay - birthDay;

                // Adjust if the birthday hasn't occurred yet this year
                if (monthDiff < 0 || (monthDiff === 0 && dayDiff < 0)) {
                    age--;
                }

                // Handle cases where age is less than 1 year (0-11 months)
                if (age < 1) {
                    // Calculate the total months old, considering potential negative month differences
                    let monthsOld = (currentYear - birthYear) * 12 + (currentMonth - birthMonth);
                    if (monthsOld < 0) {
                        monthsOld += 12; // Adjust if the month difference is negative (future birth date or invalid data)
                    }
                    console.log(`Months Old: ${monthsOld}`); // Log to check

                    // Handle 0-5 months and 6-11 months
                    if (monthsOld >= 0 && monthsOld <= 5) {
                        ageGroups["0-5 Months"]++;
                    } else if (monthsOld >= 6 && monthsOld <= 11) {
                        ageGroups["6-11 Months"]++;
                    }
                } 
                // Group for 1 year old and above
                else if (age >= 1 && age <= 5) {
                    ageGroups["1-5 Years Old"]++;
                } else if (age >= 6 && age <= 12) {
                    ageGroups["6-12 Years Old"]++;
                } else if (age >= 13 && age <= 17) {
                    ageGroups["13-17 Years Old"]++;
                } else if (age >= 18 && age <= 59) {
                    ageGroups["18-59 Years Old"]++;
                } else {
                    ageGroups["60 and above"]++;
                }
                
                totalResidents++;
            }
        });

        // Log the final counts for debugging
        console.log("Age Groups:", ageGroups);
        
        // Calculate percentages for each age group
        const ageGroupPercentages = {};
        Object.keys(ageGroups).forEach(group => {
            ageGroupPercentages[group] = totalResidents > 0 
                ? ((ageGroups[group] / totalResidents) * 100).toFixed(2) + "%" 
                : "0%";
        });

        res.json({ ageGroups, ageGroupPercentages, totalResidents });
    } catch (error) {
        console.error("Error fetching resident data:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});


app.get("/rqtAll", isLogin, isAnn, myReq, (req, res) => {
    console.log("User Access Level:", req.session.access);  // Log the access level
    if (req.session.access !== 1) return res.redirect("/"); // If access is not 0, redirect to home
    res.render("rqtAll", { layout: "layout", title: "Request", activePage: "rqt" });
});

const myRqtView = async (req, res) => {
    try {
        if (!req.user) {
            console.log("User is not logged in.");
            return res.redirect("/");
        }

        const requestId = req.params.id;
        console.log("🔎 Request ID:", requestId);

        if (!ObjectId.isValid(requestId)) {
            console.log("❌ Invalid request ID format.");
            return res.status(400).send("Invalid request ID.");
        }

        const objectIdRequestId = new ObjectId(requestId);

        // Ensure sessionUserId is an ObjectId
        let sessionUserId = req.user._id;
        if (typeof sessionUserId === "string" && ObjectId.isValid(sessionUserId)) {
            sessionUserId = new ObjectId(sessionUserId);
        }

        console.log("✅ Converted sessionUserId:", sessionUserId);

        // Fetch the specific request
        const request = await db.collection("request").findOne({
            _id: objectIdRequestId,
            requestBy: sessionUserId,  // Ensure this matches the stored ObjectId
            archive: { $in: [0, "0"] } // Ensure not archived
        });

        if (!request) {
            console.log("❌ Request not found.");
            return res.status(404).send("Request not found.");
        }

        console.log("✅ Request Found:", request);

        // Fetch resident details (where requestBy matches resident._id)
        let resident = null;
        if (request.requestBy) {
            resident = await db.collection("resident").findOne({
                _id: new ObjectId(request.requestBy)
            });
        }

        console.log("👤 Resident Found:", resident);

        // Fetch all documents related to this request
        const documents = await db.collection("document")
            .find({ reqId: objectIdRequestId })
            .toArray();

        console.log(`📄 Documents Found: ${documents.length}`);

        // Attach documents to the request object
        request.documents = documents;

        // Render the EJS page with the data
        res.render("rqtView", { request, resident, documents, layout: "layout", title: "Request", activePage: "rqt"  });

    } catch (err) {
        console.error("⚠️ Error in myRqtView:", err);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/";</script>');
    }
};

const generateRandomPassword = () => {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    let password = "";
    for (let i = 0; i < 12; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
};

app.post("/forgotX", async (req, res) => {
    try {
        const { username, email } = req.body;

        if (!username) {
            return res.redirect("/forgot?error=" + encodeURIComponent("Username is required"));
        }

        const query = { username };
        if (email) query.email = email;

        const user = await db.collection("resident").findOne(query);

        if (!user) {
            return res.redirect("/forgot?error=" + encodeURIComponent("Invalid Credentials, Try Again!"));
        }

        const newPassword = generateRandomPassword();

        await db.collection("resident").updateOne(
            { _id: user._id },
            { $set: { password: newPassword, reset: 1 } }
        );

        let emailToSend = user.email;

        if (!emailToSend && user.headId) {
            const familyHead = await db.collection("resident").findOne({ _id: new ObjectId(user.headId) });
            emailToSend = familyHead ? familyHead.email : null;
        }

        if (!emailToSend) {
            return res.redirect("/forgot?error=" + encodeURIComponent("No email found for user or family head"));
        }

        // ✅ Nodemailer email content
        const mailOptions = {
            from: '"Barangay System" <yourgmail@gmail.com>',
            to: emailToSend,
            subject: 'Password Reset Request',
            html: `
                <p>A temporary password has been generated for your account:</p>
                <p style="font-size: 18px; font-weight: bold;">🔑 ${newPassword}</p>
                <p>Please log in and change your password immediately for security reasons.</p>
            `,
        };

        try {
            await transporter.sendMail(mailOptions);
        } catch (error) {
            console.error('Error sending email:', error);
            return res.redirect("/forgot?error=" + encodeURIComponent("Failed to send email"));
        }

        res.render("passSuccess", { username, email: emailToSend, error : "Password Reset Successfully!" });

    } catch (error) {
        console.error("Error resetting password:", error);
        res.redirect("/forgot?error=" + encodeURIComponent("Internal Server Error"));
    }
});


app.get("/rqtSuccess", isLogin, isReq, (req, res) => res.render("rqtSuccess", { layout: "design", title: "Services", activePage: "rqt" }));
app.get('/rqtView/:id', isLogin, myRqtView);

app.get("/resv/:id", isLogin, async (req, res) => {
    try {
        const residentId = new ObjectId(req.params.id);
        const resident = await db.collection("resident").findOne({ _id: residentId });

        if (!resident) {
            return res.status(404).send('<script>alert("Resident not found!"); window.location="/rsd";</script>');
        }

        const families = db.collection("family");
        const households = db.collection("household");

        let familyData = null;
        if (resident.familyId) {
            familyData = await families.findOne({ _id: new ObjectId(resident.familyId) });
        }

        // Fetch Household Details (entire document)
        let householdData = null;
        if (resident.householdId) {
            householdData = await households.findOne({ _id: new ObjectId(resident.householdId) });
        }

        // Fetch Family Members
        let familyMembers = [];
        if (resident.familyId) {
            familyMembers = await db.collection("resident").find({ familyId: resident.familyId }).toArray();
        
            // Calculate age for each family member
            familyMembers = familyMembers.map(member => {
                let age = "Age Unknown";
                if (member.bYear && member.bMonth && member.bDay) {
                    const birthDate = new Date(member.bYear, member.bMonth - 1, member.bDay);
                    const today = new Date();
                    
                    let years = today.getFullYear() - birthDate.getFullYear();
                    let months = today.getMonth() - birthDate.getMonth();
                    let days = today.getDate() - birthDate.getDate();
        
                    if (days < 0) {
                        months--; // Adjust if days are negative
                        days += new Date(today.getFullYear(), today.getMonth(), 0).getDate(); // Get last month's days
                    }
                    if (months < 0) {
                        years--; // Adjust if months are negative
                        months += 12;
                    }
        
                    if (years < 1) {
                        if (months === 0) {
                            age = "Less than a month old";
                        } else {
                            age = `${months} Month${months > 1 ? "s" : ""} Old`;
                        }
                    } else {
                        age = `${years} Year${years > 1 ? "s" : ""} Old`;
                    }
                }
                return { ...member, age };
            });
        }
        

        // Calculate Age and Format Birthday
        let age = "--";
        let birthday = "--";
        
        if (resident.bYear && resident.bMonth && resident.bDay) {
            const birthDate = new Date(resident.bYear, resident.bMonth - 1, resident.bDay);
            const today = new Date();
        
            const diffInMilliseconds = today - birthDate;
            const diffInDays = Math.floor(diffInMilliseconds / (1000 * 60 * 60 * 24));
            const diffInMonths = Math.floor(diffInDays / 30.44); // Average days in a month
            const diffInYears = Math.floor(diffInMonths / 12);
        
            if (diffInDays < 30) {
                age = "Less than a Month";
            } else if (diffInMonths < 12) {
                age = `${diffInMonths} ${diffInMonths === 1 ? "month old" : "months old"}`;
            } else {
                age = `${diffInYears} ${diffInYears === 1 ? "year old" : "years old"}`;
            }
        
            const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
            birthday = `${monthNames[resident.bMonth - 1]} ${resident.bDay}, ${resident.bYear}`;
        }

        familyMembers.sort((a, b) => {
            const ageA = parseInt(a.age) || 0; // Convert "29 Years Old" to 29
            const ageB = parseInt(b.age) || 0;
            return ageB - ageA; // Descending order
        });
        

        // Fetch Resident's Requests & Documents
        const requests = await db.collection("request").find({ requestBy: residentId, archive: { $in: [0, "0"] } }).toArray();
        const requestIds = requests.map(req => req._id);
        const documents = requestIds.length ? await db.collection("document").find({ reqId: { $in: requestIds } }).toArray() : [];

        // Fetch Complainee Records where resident is a complainee
        const complaineeRecords = await db.collection("complainees").find({ residentId: residentId }).toArray();
        const caseIds = complaineeRecords.map(c => new ObjectId(c.caseId));

        // Fetch Cases related to the resident as a complainee
        const cases = caseIds.length ? await db.collection("cases").find({ _id: { $in: caseIds } }).toArray() : [];

        // Fetch Complainants from the matched cases
        const complainants = caseIds.length ? await db.collection("complainants").find({ caseId: { $in: caseIds } }).toArray() : [];

        // Fetch Schedules related to these cases
        const schedules = caseIds.length ? await db.collection("schedule").find({ caseId: { $in: caseIds } }).toArray() : [];

        res.render("resv", {
            layout: "layout",
            title: "Resident Details",
            activePage: "rsd",
            resident,
            requests,
            documents,
            cases,
            schedules,
            complainants,
            complainees: complaineeRecords,
            familyData,  // ✅ Added Poverty Level
            householdData,  // ✅ Now passing the entire household data
            familyMembers,  // ✅ Passing all residents with the same familyId
            age,            // ✅ Added Age
            birthday,        // ✅ Added Birthday
            back: "rsd"
        });

    } catch (err) {
        console.error("❌ Error fetching resident details:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/rsd";</script>');
    }
});



app.get("/rsdView2/:id", isLogin, async (req, res) => {
    try {
        const residentId = new ObjectId(req.params.id);
        const resident = await db.collection("resident").findOne({ _id: residentId });

        if (!resident) {
            return res.status(404).send('<script>alert("Resident not found!"); window.location="/rsd";</script>');
        }

        const families = db.collection("family");
        const households = db.collection("household");

        // Fetch Family Poverty Level
        let familyPoverty = "Unidentified Status";
        if (resident.familyId) {
            const family = await families.findOne({ _id: new ObjectId(resident.familyId) });
            if (family) {
                familyPoverty = family.poverty || "Unidentified Status";
            }
        }

        // Fetch Household Details (entire document)

        let familyData = null;
        if (resident.familyId) {
            familyData = await families.findOne({ _id: new ObjectId(resident.familyId) });
        }

        // Fetch Household Details (entire document)
        let householdData = null;
        if (resident.householdId) {
            householdData = await households.findOne({ _id: new ObjectId(resident.householdId) });
        }

        // Fetch Family Members
        let familyMembers = [];
        if (resident.familyId) {
            familyMembers = await db.collection("resident").find({ familyId: resident.familyId }).toArray();
        
            // Calculate age for each family member
            familyMembers = familyMembers.map(member => {
                let age = "Age Unknown";
                if (member.bYear && member.bMonth && member.bDay) {
                    const birthDate = new Date(member.bYear, member.bMonth - 1, member.bDay);
                    const today = new Date();
                    
                    let years = today.getFullYear() - birthDate.getFullYear();
                    let months = today.getMonth() - birthDate.getMonth();
                    let days = today.getDate() - birthDate.getDate();
        
                    if (days < 0) {
                        months--; // Adjust if days are negative
                        days += new Date(today.getFullYear(), today.getMonth(), 0).getDate(); // Get last month's days
                    }
                    if (months < 0) {
                        years--; // Adjust if months are negative
                        months += 12;
                    }
        
                    if (years < 1) {
                        if (months === 0) {
                            age = "Less than a month old";
                        } else {
                            age = `${months} Month${months > 1 ? "s" : ""} Old`;
                        }
                    } else {
                        age = `${years} Year${years > 1 ? "s" : ""} Old`;
                    }
                }
                return { ...member, age };
            });
        }
        

        // Calculate Age and Format Birthday
        let age = "--";
        let birthday = "--";
        
        if (resident.bYear && resident.bMonth && resident.bDay) {
            const birthDate = new Date(resident.bYear, resident.bMonth - 1, resident.bDay);
            const today = new Date();
        
            const diffInMilliseconds = today - birthDate;
            const diffInDays = Math.floor(diffInMilliseconds / (1000 * 60 * 60 * 24));
            const diffInMonths = Math.floor(diffInDays / 30.44); // Average days in a month
            const diffInYears = Math.floor(diffInMonths / 12);
        
            if (diffInDays < 30) {
                age = "Less than a Month";
            } else if (diffInMonths < 12) {
                age = `${diffInMonths} ${diffInMonths === 1 ? "month old" : "months old"}`;
            } else {
                age = `${diffInYears} ${diffInYears === 1 ? "year old" : "years old"}`;
            }
        
            const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
            birthday = `${monthNames[resident.bMonth - 1]} ${resident.bDay}, ${resident.bYear}`;
        }

        familyMembers.sort((a, b) => {
            const ageA = parseInt(a.age) || 0; // Convert "29 Years Old" to 29
            const ageB = parseInt(b.age) || 0;
            return ageB - ageA; // Descending order
        });
        

        // Fetch Resident's Requests & Documents
        const requests = await db.collection("request").find({ requestBy: residentId, archive: { $in: [0, "0"] } }).toArray();
        const requestIds = requests.map(req => req._id);
        const documents = requestIds.length ? await db.collection("document").find({ reqId: { $in: requestIds } }).toArray() : [];

        // Fetch Complainee Records where resident is a complainee
        const complaineeRecords = await db.collection("complainees").find({ residentId: residentId }).toArray();
        const caseIds = complaineeRecords.map(c => new ObjectId(c.caseId));

        // Fetch Cases related to the resident as a complainee
        const cases = caseIds.length ? await db.collection("cases").find({ _id: { $in: caseIds } }).toArray() : [];

        // Fetch Complainants from the matched cases
        const complainants = caseIds.length ? await db.collection("complainants").find({ caseId: { $in: caseIds } }).toArray() : [];

        // Fetch Schedules related to these cases
        const schedules = caseIds.length ? await db.collection("schedule").find({ caseId: { $in: caseIds } }).toArray() : [];

        res.render("resv", {
            layout: "layout",
            title: "Resident Details",
            activePage: "rsd",
            resident,
            requests,
            documents,
            cases,
            schedules,
            complainants,
            complainees: complaineeRecords,
            familyData,  // ✅ Added Poverty Level
            householdData,  // ✅ Now passing the entire household data
            familyMembers,  // ✅ Passing all residents with the same familyId
            age,            // ✅ Added Age
            birthday ,       // ✅ Added Birthday
            back: "hsh"
        });

    } catch (err) {
        console.error("❌ Error fetching resident details:", err);
        res.status(500).send('<script>alert("Internal Server Error! Please try again."); window.location="/rsd";</script>');
    }
});


app.post("/cmn", async (req, res) => {
    try {
        const { caseNo, complainants, complainees, type, month, day, year, hour, minute, zone } = req.body;

        // Parse complainees from JSON format
        const complaineesArray = JSON.parse(complainees);

        // Insert a new case in "cases" collection with manually inputted caseNo
        const newCase = await db.collection("cases").insertOne({
            caseNo: caseNo, // Manually inputted case number
            type: type,
            status: "Pending",
            month: month,
            day: day,
            year: year,
            hour: hour,
            minute: minute,
            zone: zone,
            archive: 0, // ✅ Added archive field set to 0
            createdAt: new Date()
        });

        // Get the generated case ID
        const caseId = newCase.insertedId;

        // Insert complainants into "complainants" collection
        await db.collection("complainants").insertOne({
            caseId: caseId,
            name: complainants, // Array of complainant names
            createdAt: new Date()
        });

        // Insert complainees into "complainees" collection
        await db.collection("complainees").insertOne({
            caseId: caseId,
            name: complaineesArray, // Array of selected resident _id values
            createdAt: new Date()
        });

        res.redirect("/blot"); // Redirect to complaints list after submission
    } catch (err) {
        console.error("Error adding complaint:", err);
        res.status(500).send('<script>alert("Internal Server Error!"); window.location="/cmn";</script>');
    }
});

app.post("/arcCase/:id", async (req, res) => { 
    try {
        const caseId = req.params.id;
        if (!ObjectId.isValid(caseId)) return res.status(400).send("Invalid case ID");

        const caseObjectId = new ObjectId(caseId);
        const casesCollection = db.collection("cases");

        const updateResult = await casesCollection.updateOne(
            { _id: caseObjectId },
            { $set: { archive: 1 } }
        );

        if (updateResult.modifiedCount === 0) return res.status(404).send("Case not found.");

        res.redirect("/blot");  
    } catch (error) {
        console.error("Error archiving case:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/export-residents-pdf", async (req, res) => {
    try {
        const residents = await db.collection("resident").find().toArray();
        const doc = new PDFDocument({ margin: 50 });
        const fileName = `Residents_Report_${Date.now()}.pdf`;
        const filePath = path.join(__dirname, "public", "reports", fileName);

        if (!fs.existsSync(path.join(__dirname, "public", "reports"))) {
            fs.mkdirSync(path.join(__dirname, "public", "reports"), { recursive: true });
        }

        const writeStream = fs.createWriteStream(filePath);
        doc.pipe(writeStream);

        // Title
        doc.fontSize(20).fillColor("#1F4E79").text("Residents Report", { align: "center" }).moveDown(2);

        // Categorization
        const ageGroups = {
            "0-5 Months": [],
            "6-11 Months": [],
            "1-5 Years Old": [],
            "6-12 Years Old": [],
            "13-17 Years Old": [],
            "18-59 Years Old": [],
            "15-30 (SK Voters)": [],
            "59 & Above (Senior Citizen)": []
        };
        
        const genderGroups = { Male: [], Female: [], Other: [] };
        const priorityGroups = {};

        residents.forEach(r => {
            const age = calculateAge(r.bMonth, r.bDay, r.bYear);
            
            if (age < 1) {
                const monthsOld = moment().diff(`${r.bYear}-${r.bMonth}-${r.bDay}`, "months");
                if (monthsOld <= 5) ageGroups["0-5 Months"].push(r);
                else ageGroups["6-11 Months"].push(r);
            } else if (age >= 1 && age <= 5) ageGroups["1-5 Years Old"].push(r);
            else if (age >= 6 && age <= 12) ageGroups["6-12 Years Old"].push(r);
            else if (age >= 13 && age <= 17) ageGroups["13-17 Years Old"].push(r);
            else if (age >= 18 && age <= 59) ageGroups["18-59 Years Old"].push(r);
            if (age >= 15 && age <= 30) ageGroups["15-30 (SK Voters)"].push(r);
            if (age >= 59) ageGroups["59 & Above (Senior Citizen)"].push(r);

            // Gender Grouping
            const genderKey = r.gender?.toLowerCase() === "male" ? "Male" : r.gender?.toLowerCase() === "female" ? "Female" : "Other";
            genderGroups[genderKey].push(r);

            // Priority Grouping
            if (r.priority) {
                if (!priorityGroups[r.priority]) {
                    priorityGroups[r.priority] = [];
                }
                priorityGroups[r.priority].push(r);
            }
        });

        function addCategorySection(title, group) {
            doc.fontSize(16).fillColor("#1F4E79").text(title).moveDown(0.5);
            doc.fillColor("#000000").fontSize(12);
            Object.keys(group).forEach(category => {
                doc.fontSize(14).text(`${category}: ${group[category].length} residents`).moveDown(0.3);
            });
            doc.moveDown(1);
        }

        // Add Sections
        addCategorySection("Age Distribution", ageGroups);
        addCategorySection("Gender Distribution", genderGroups);
        addCategorySection("Priority Groups", priorityGroups);

        // Finalize PDF
        doc.end();

        writeStream.on("finish", () => {
            res.download(filePath, fileName, (err) => {
                if (err) console.error("❌ Error downloading PDF:", err);
                fs.unlinkSync(filePath); // Delete file after download
            });
        });
    } catch (error) {
        console.error("❌ Error exporting residents as PDF:", error);
        res.status(500).json({ message: "Error exporting residents data." });
    }
});

function calculateAge(bMonth, bDay, bYear) {
    if (!bMonth || !bDay || !bYear) return 0;
    const monthNumber = isNaN(bMonth) ? moment().month(bMonth).format("M") : bMonth;
    return moment().diff(`${bYear}-${monthNumber}-${bDay}`, "years");
}

// Function to calculate age
function calculateAge(bMonth, bDay, bYear) {
    if (!bMonth || !bDay || !bYear) return 0;
    const monthNumber = isNaN(bMonth) ? moment().month(bMonth).format("M") : bMonth;
    return moment().diff(`${bYear}-${monthNumber}-${bDay}`, "years");
}

app.post("/rst/:id", async (req, res) => {
    try {
        const userId = req.params.id;
        const { newPassword, confirmPassword } = req.body;

        if (!newPassword || !confirmPassword) {
            return res.send('<script>alert("Please fill in all fields."); window.history.back();</script>');
        }

        if (newPassword !== confirmPassword) {
            return res.send('<script>alert("Passwords do not match."); window.history.back();</script>');
        }

        // Update the password and delete the reset field
        await db.collection("resident").updateOne(
            { _id: new ObjectId(userId) },
            { 
                $set: { password: newPassword }, 
                $unset: { reset: 1 } // Removes the 'reset' field completely
            }
        );

        return res.send('<script>alert("Password successfully reset. Please log in."); window.location="/";</script>');

    } catch (error) {
        console.error("Error resetting password:", error);
        res.send('<script>alert("An error occurred. Please try again later."); window.location="/";</script>');
    }
});

app.get("/newRsd", isLogin, isRsd, (req, res) => res.render("newRsd", { layout: "layout", title: "New Resident", activePage: "newRsd" }));

app.get('/check-resident', async (req, res) => {
    try {
        const { houseNo, purok } = req.query;

        if (!houseNo || !purok) {
            return res.json({ exists: false });
        }

        // Check in household collection where archive is 0 or "0"
        const householdExists = await db.collection("household").findOne({
            archive: { $in: [0, "0"] }, 
            houseNo: houseNo,  // Exact match for house number
            purok: new RegExp(`^${purok}$`, "i") // Case-insensitive exact match for purok
        });

        res.json({ exists: !!householdExists });
    } catch (error) {
        console.error("Error checking household:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


app.get("/newFml/:householdId", isLogin, async (req, res) => {
    const { householdId } = req.params;

    // Example dropdown list for cities (you can fetch from a database)
    const cities = ["Science City of Muñoz", "Cabanatuan", "Talavera", "San Jose", "Quezon"];

    // Example disability types
    const pwdTypes = ["Visual Impairment", "Hearing Impairment", "Mobility Impairment", "Intellectual Disability"];

    res.render("newFml", { householdId, cities, pwdTypes, layout: "Layout", title: 'New Family', activePage: "hsh" });
});


function generateUsername(firstName, middleName, lastName, bDay, bYear) {
    if (!firstName || !middleName || !lastName) return null;
    return `${firstName.charAt(0)}${firstName.slice(-1)}${middleName.charAt(0)}${middleName.slice(-1)}.${lastName}${bDay}${bYear.slice(-2)}`.toLowerCase();
}

app.post("/add-family", async (req, res) => {
    try {
        const residents = db.collection("resident");
        const families = db.collection("family"); // Collection for family data

        const { 
            firstName, middleName, lastName, extName, birthPlace, // Added fields
            bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email, 
            soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome, position, householdId, rel // Added rel field
        } = req.body;

        // Calculate age
        const birthDate = new Date(`${bYear}-${bMonth}-${bDay}`);
        const today = new Date();
        let age = today.getFullYear() - birthDate.getFullYear();
        if (today.getMonth() < birthDate.getMonth() || (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) {
            age--;
        }

        if (age < 15) {
            return res.status(400).json({ message: "Family Head can't be a minor" });
        }

        let username = null;
        let password = null;
        if (age >= 15 && age <= 59) {
            username = generateUsername(firstName, middleName, lastName, bDay, bYear);
            password = generateRandomPassword();
        }

        // Determine resident access level
        const privilegedPositions = ["Barangay Secretary", "Punong Barangay", "Barangay Worker", "BWDO", "Barangay Clerk"];
        const access = privilegedPositions.includes(position) ? 1 : 0;

        // Convert monthlyIncome to number
        const income = monthlyIncome ? parseFloat(monthlyIncome) : 0;

        // Determine poverty level for 1-2 members
        let poverty = "Non-Indigent"; // Default
        if (income < 7500) {
            poverty = "Indigent";
        } else if (income >= 7500 && income <= 10000) {
            poverty = "Low Income";
        }

        // Create a new family document
        const newFamily = {
            familyIncome: income,
            poverty, // Determined based on income
            archive: 0,
            updatedAt: new Date(),
            createdAt: new Date(),
            householdId,
        };

        // Insert into the `family` collection and get the newly created _id
        const familyResult = await families.insertOne(newFamily);
        const familyId = familyResult.insertedId; // Get the newly created family's _id

        // Create the resident document with familyId and householdId
        const newResident = {
            firstName, middleName, lastName, extName, birthPlace, // Included the new fields
            bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email,
            soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome: income, position,
            archive: 0,
            reset: 0,
            createdAt: new Date(),
            updatedAt: new Date(),
            successAt: null,
            username,
            password,
            role: "Head", // Assign role as Head
            familyId, // Link the resident to the newly created family
            householdId, // ✅ Added householdId
            access, // Set access level
            rel // ✅ Added rel field
        };

        await residents.insertOne(newResident);

        // ✅ Redirect to household view after success
        res.redirect(`/hshView/${householdId}`);
    } catch (error) {
        console.error("Error adding resident:", error);
        res.status(500).send('<script>alert("Error adding resident"); window.location="/";</script>');
    }
});



app.get("/newMem", isLogin, async (req, res) => {
    const { familyId } = req.params;
    const { householdId } = req.query; // Extract householdId from query params

    res.render("newMem", { 
        familyId, 
        householdId, 
        layout: "Layout", 
        title: 'New Member', 
        activePage: "hsh" 
    });
});



app.get("/newMem2", isLogin, async (req, res) => {
    const { familyId } = req.params;
    const { householdId } = req.query; // Extract householdId from query params

    res.render("newMem2", { 
        familyId, 
        householdId, 
        layout: "Layout", 
        title: 'New Member', 
        activePage: "hsh" 
    });
});


app.get("/nonRes", isLogin, async (req, res) => {

    res.render("nonRes", {
        layout: "Layout", 
        title: 'New Member', 
        activePage: "rsd" 
    });
});

app.post("/add-member", async (req, res) => {
    try {
        const residents = db.collection("resident");

        const { 
            firstName, middleName, lastName, extName, birthPlace, 
            bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email, 
            soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome, position, 
            birthHeight, birthWeight, healthCenter, rel, nationality, religion, education, houseNo, purok, headId 
        } = req.body;

        // Calculate age
        const birthDate = new Date(`${bYear}-${bMonth}-${bDay}`);
        const today = new Date();
        let age = today.getFullYear() - birthDate.getFullYear();
        if (today.getMonth() < birthDate.getMonth() || 
            (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) age--;

        // Generate username & password only if age is between 15-59
        let username = null;
        let password = null;
        if (age >= 15 && age <= 59) {
            username = generateUsername(firstName, middleName, lastName, bDay, bYear);
            password = generateRandomPassword();
        }

        // Determine resident access level
        const privilegedPositions = ["Barangay Secretary", "Punong Barangay", "Barangay Worker", "BWDO", "Barangay Clerk"];
        const access = privilegedPositions.includes(position) ? 1 : 0;

        const income = monthlyIncome ? parseFloat(monthlyIncome) : 0;

        // Insert the new resident
        const newResident = {
            firstName, middleName, lastName, extName, birthPlace,
            bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email,
            soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome: income, position,
            birthHeight, birthWeight, healthCenter, rel, nationality, religion, education, houseNo, purok,
            archive: 0,
            reset: 0,
            createdAt: new Date(),
            updatedAt: new Date(),
            successAt: null,
            username,
            password,
            role: "Member",
            access,
        };

        await residents.insertOne(newResident);

        // Redirect immediately to avoid waiting for email
        res.redirect("/res");

        // Send email in background
        (async () => {
            try {
                const shouldSendEmail = true;
                let recipientEmail = email;

                if (shouldSendEmail && !recipientEmail && rel === "member" && headId) {
                    const headResident = await db.collection("resident").findOne({ _id: new ObjectId(headId) });
                    if (headResident && headResident.email) recipientEmail = headResident.email;
                }

                if (shouldSendEmail && recipientEmail) {
                    const mailOptions = {
                        from: "johnniebre1995@gmail.com",
                        to: recipientEmail,
                        subject: "Your Resident Account Details",
                        text: `Dear ${firstName},\n\nYour resident account has been created.\nUsername: ${username}\nPassword: ${password}\n\nPlease keep your credentials secure.\n\nThank you.`,
                        html: `<p>Dear <strong>${firstName}</strong>,</p>
                               <p>Your resident account has been created.</p>
                               <p><strong>Username:</strong> ${username}</p>
                               <p><strong>Password:</strong> ${password}</p>
                               <p>Please keep your credentials secure.</p>
                               <p>Thank you.</p>`
                    };
                    await transporter.sendMail(mailOptions);
                }
            } catch (err) {
                console.error("Error sending resident email:", err);
            }
        })();

    } catch (error) {
        console.error("Error adding resident:", error);
        res.status(500).send('<script>alert("Error adding resident"); window.location="/";</script>');
    }
});

app.post("/add-member2", async (req, res) => {
    try {
        const residents = db.collection("resident");

        const { 
            firstName, middleName, lastName, extName, birthPlace, 
            bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email, 
            soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome, position, 
            birthHeight, birthWeight, healthCenter, rel, nationality, religion, education, houseNo, purok, headId 
        } = req.body;

        // Calculate age
        const birthDate = new Date(`${bYear}-${bMonth}-${bDay}`);
        const today = new Date();
        let age = today.getFullYear() - birthDate.getFullYear();
        if (today.getMonth() < birthDate.getMonth() || 
            (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) age--;

        // Generate username & password only if age is between 15-59
        let username = null;
        let password = null;
        if (age >= 15 && age <= 59) {
            username = generateUsername(firstName, middleName, lastName, bDay, bYear);
            password = generateRandomPassword();
        }

        // Determine resident access level
        const privilegedPositions = ["Barangay Secretary", "Punong Barangay", "Barangay Worker", "BWDO", "Barangay Clerk"];
        const access = privilegedPositions.includes(position) ? 1 : 0;

        const income = monthlyIncome ? parseFloat(monthlyIncome) : 0;

        // Insert the new resident
        const newResident = {
            firstName, middleName, lastName, extName, birthPlace,
            bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email,
            soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome: income, position,
            birthHeight, birthWeight, healthCenter, rel, nationality, religion, education, houseNo, purok,
            archive: 1,
            reset: 0,
            createdAt: new Date(),
            updatedAt: new Date(),
            successAt: null,
            username,
            password,
            role: "Member",
            access,
        };

        await residents.insertOne(newResident);

        // Redirect immediately to avoid waiting for email
        res.redirect("/archiv");

    } catch (error) {
        console.error("Error adding resident:", error);
        res.status(500).send('<script>alert("Error adding resident"); window.location="/";</script>');
    }
});

app.post("/add-memberR", async (req, res) => {
    try {
        const residents = db.collection("resident");

        const { 
            firstName, middleName, lastName, extName, birthPlace, 
            bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email, 
            soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome, position, 
            birthHeight, birthWeight, healthCenter, rel, nationality, religion, education, houseNo, purok, headId 
        } = req.body;

        // Calculate age
        const birthDate = new Date(`${bYear}-${bMonth}-${bDay}`);
        const today = new Date();
        let age = today.getFullYear() - birthDate.getFullYear();
        if (today.getMonth() < birthDate.getMonth() || 
            (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) age--;

        // Generate username & password only if age is between 15-59
        let username = null;
        let password = null;
        if (age >= 15 && age <= 59) {
            username = generateUsername(firstName, middleName, lastName, bDay, bYear);
            password = generateRandomPassword();
        }

        // Determine access level
        const privilegedPositions = ["Barangay Secretary", "Punong Barangay", "Barangay Worker", "BWDO", "Barangay Clerk"];
        const access = privilegedPositions.includes(position) ? 1 : 0;

        const income = monthlyIncome ? parseFloat(monthlyIncome) : 0;

        // Insert the new resident
        const newResident = {
            firstName, middleName, lastName, extName, birthPlace,
            bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email,
            soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome: income, position,
            birthHeight, birthWeight, healthCenter, rel, nationality, religion, education, houseNo, purok,
            archive: 1,
            reset: 0,
            verify: 1,
            createdAt: new Date(),
            updatedAt: new Date(),
            successAt: null,
            username,
            password,
            role: "Member",
            access,
        };

        await residents.insertOne(newResident);

        // Redirect immediately
        res.redirect("/regSuccess");

        // Send email in background
        (async () => {
            try {
                const shouldSendEmail = true;
                let recipientEmail = email;

                // Use head's email if personal email is not provided
                if (shouldSendEmail && !recipientEmail && headId) {
                    const headResident = await db.collection("resident").findOne({ _id: new ObjectId(headId) });
                    if (headResident && headResident.email) recipientEmail = headResident.email;
                }

                if (shouldSendEmail && recipientEmail) {
                    const mailOptions = {
                        from: "johnniebre1995@gmail.com",
                        to: recipientEmail,
                        subject: "Account Registration",
                        text: `Dear ${firstName},\n\nYour registration has been submitted successfully! \n\nThank you.`,
                        html: `
                            <p style="font-size: 18px; text-align: center;">Your registration has been submitted successfully!</p>
                            <div style="font-size: 14px; text-align: center; font-weight: 500;">
                                The Barangay Secretary will verify your details within 24 hours on business days and will notify you via email regarding its status. Weekends are excluded.
                            </div>`
                    };
                    await transporter.sendMail(mailOptions);
                }
            } catch (err) {
                console.error("Error sending resident email:", err);
            }
        })();

    } catch (error) {
        console.error("Error adding resident:", error);
        res.status(500).send('<script>alert("Error adding resident"); window.location="/";</script>');
    }
});


app.post("/add-member2", async (req, res) => {
    try {
        const residents = db.collection("resident");
        const families = db.collection("family");

        const { 
            firstName, middleName, lastName, extName, birthPlace, 
            bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email, 
            soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome, position, 
            householdId, familyId,
            birthHeight, birthWeight, healthCenter, // ✅ Added new fields
            rel // ✅ Added rel field
        } = req.body;

        // Calculate age
        const birthDate = new Date(`${bYear}-${bMonth}-${bDay}`);
        const today = new Date();
        let age = today.getFullYear() - birthDate.getFullYear();
        if (today.getMonth() < birthDate.getMonth() || (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) {
            age--;
        }

        // Determine resident access level
        const privilegedPositions = ["Barangay Secretary", "Punong Barangay", "Barangay Worker", "BWDO", "Barangay Clerk"];
        const access = privilegedPositions.includes(position) ? 0 : 0;

        // Convert monthlyIncome to a number
        const income = monthlyIncome ? parseFloat(monthlyIncome) : 0;

        // Insert the new resident into the `resident` collection
        const newResident = {
            firstName, middleName, lastName, extName, birthPlace,
            bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email,
            soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome: income, position,
            birthHeight, birthWeight, healthCenter, // ✅ Added new fields
            rel, // ✅ Added rel field
            archive: 1,
            reset: 0,
            createdAt: new Date(),
            updatedAt: new Date(),
            successAt: null,
            visitor: 1,
            role: "Member",
            access,
        };

        await residents.insertOne(newResident);

        // **Redirect to household view after success**
        res.redirect(`rsd`);
    } catch (error) {
        console.error("Error adding resident:", error);
        res.status(500).send('<script>alert("Error adding resident"); window.location="/";</script>');
    }
});


app.get("/search-resident", async (req, res) => {
    try {
        if (!db) {
            console.error("❌ Database connection not initialized.");
            return res.status(500).json({ error: "Database connection error." });
        }

        let query = req.query.q?.trim(); // Trim whitespace
        console.log("🔎 Received Query:", query);

        if (!query) {
            return res.status(400).json({ error: "Query parameter is required" });
        }

        console.log("🛠 Executing MongoDB Query...");

        // Search in `resident` collection
        let results = await db.collection("resident")
            .find({
                $or: [
                    { firstName: { $regex: query, $options: "i" } },
                    { middleName: { $regex: query, $options: "i" } },
                    { lastName: { $regex: query, $options: "i" } }
                ]
            })
            .limit(10) // Limit results for better performance
            .project({ firstName: 1, middleName: 1, lastName: 1 }) // Fetch only necessary fields
            .toArray();

        // Convert `_id` to string
        results = results.map(resident => ({
            ...resident,
            _id: resident._id, // Ensure `_id` is a string
        }));

        console.log("📋 Found Residents:", results.length, "matches");
        res.json(results);
    } catch (error) {
        console.error("❌ Error fetching residents:", error.message, error.stack);
        res.status(500).json({ error: error.message });
    }
});

app.post("/cases", async (req, res) => {
    try {
        const { 
            caseNo, 
            complainants: complainantsJSON, 
            respondents: respondentsJSON, 
            caseTypes: caseTypesJSON,
            remarks // ✅ add remarks from form
        } = req.body;
        
        // Parse JSON data
        const complainants = JSON.parse(complainantsJSON);
        const respondents = JSON.parse(respondentsJSON);
        const caseTypes = JSON.parse(caseTypesJSON);

        // Validate required fields
        if (!caseNo || !complainants?.length || !respondents?.length || !caseTypes?.length) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        // Process residents (complainants and respondents)
        const processPerson = async (person) => {
            if (person.isManual) {
                // For manual entries, create new resident record
                const result = await db.collection("resident").insertOne({
                    firstName: person.firstName,
                    middleName: person.middleName,
                    lastName: person.lastName,
                    extName: person.extName,
                    archive: "1", // Mark as non-resident
                    createdAt: new Date(),
                    updatedAt: new Date()
                });
                return result.insertedId;
            } else {
                // For existing residents, use their ID
                return new ObjectId(person._id);
            }
        };

        // Process all complainants and respondents in parallel
        const [complainantIds, respondentIds] = await Promise.all([
            Promise.all(complainants.map(processPerson)),
            Promise.all(respondents.map(processPerson))
        ]);

        // Create the case record
        const caseData = {
            caseNo,
            status: "Pending",
            archive: "0",
            complainants: complainantIds,
            respondents: respondentIds,
            type: caseTypes,
            remarks: remarks || "", // ✅ save remarks (empty string if none)
            createdAt: new Date(),
            updatedAt: new Date()
        };

        const result = await db.collection("cases").insertOne(caseData);
        
        // Ensure status is also set to "Pending"
        await db.collection("cases").updateOne(
            { _id: result.insertedId },
            { $set: { status: "Pending" } }
        );

        res.redirect("/blot");
    } catch (error) {
        console.error("Error creating case:", error);
        res.status(500).json({ error: "Internal Server Error", details: error.message });
    }
});
function safeParseJSON(str) {
  try {
    return str ? JSON.parse(str) : [];
  } catch {
    return [];
  }
}
app.post("/cases/update/:id", async (req, res) => {
  try {
    const { caseNo, complainants, respondents, caseTypes, remarks } = req.body;

    const caseId = new ObjectId(req.params.id);

    const updateData = {
      caseNo,
      remarks: remarks || "",
      updatedAt: new Date()
    };

    if (complainants) updateData.complainants = JSON.parse(complainants);
    if (respondents) updateData.respondents = JSON.parse(respondents);
    if (caseTypes) updateData.type = JSON.parse(caseTypes);

    await db.collection("cases").updateOne(
      { _id: caseId },
      { $set: updateData }
    );

    res.redirect("/blot");
  } catch (err) {
    console.error("Error updating case:", err);
    res.status(500).send("Error updating case");
  }
});

app.get('/check-case-number', async (req, res) => { // Renamed for clarity
    try {
        const { caseNo } = req.query; // Only expect caseNo

        if (!caseNo) {
            // If caseNo is empty, consider it as not existing for this check
            return res.json({ exists: false }); 
        }

        // Check in the 'cases' collection
        const caseExists = await db.collection("cases").findOne({
            caseNo: caseNo // Exact match for case number
        });

        res.json({ exists: !!caseExists }); // !! converts truthy/falsy to true/false
    } catch (error) {
        console.error("Error checking case number:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/verify-password", requireAuth, async (req, res) => {
    try {
        const { currentPassword } = req.body;
        const userId = req.session.userId;

        const user = await db.collection("resident").findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ valid: false, message: "User not found" });
        }

        if (user.password === currentPassword) {
            return res.json({ valid: true });
        } else {
            return res.json({ valid: false });
        }
    } catch (err) {
        console.error("❌ Error verifying password:", err);
        res.status(500).json({ valid: false });
    }
});

app.post("/generate-households", async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ success: false, message: "Database not connected" });
        }

        const householdCollection = db.collection("household");
        const puroks = ["Dike", "Shortcut", "Maharlika Highway", "Perigola", "Cantarilla", "Bagong Daan"];
        const householdsToInsert = [];

        // Helper function to get a random item from an array
        const getRandomItem = (array) => array[Math.floor(Math.random() * array.length)];

        // Define random options for each field
        const ownershipOptions = ["Owned", "Rented", "Informal Settler", "Government Housing"];
        const houseTypeOptions = ["Makeshift", "Nipa Hut", "Semi Concrete", "Fully Concrete"];
        const wallMaterialOptions = ["Bamboo", "Wood", "Hollow Blocks", "Light Materials"];
        const roofMaterialOptions = ["Galvanized Iron", "Nipa", "Wood", "Light Materials"];
        const flooringMaterialOptions = ["Cemented", "Wood", "Bamboo", "Tiles"];
        const toiletTypeOptions = ["Open Pit", "Shared", "Private with Flush", "None"];
        const waterSourceOptions = ["Deep Well", "Pump", "Faucet", "Bottled Water"];
        const electricityOptions = ["Electricity", "Solar", "Caserole Lamp", "Candle", "Generator"];

        for (const purok of puroks) {
            for (let i = 1; i <= 20; i++) {
                const householdData = {
                    // Generate unique ID, MongoDB will handle this automatically
                    // The house number will be randomly assigned from 1 to 100 for variety
                    houseNo: (Math.floor(Math.random() * 100) + 1).toString(),
                    purok: purok,
                    ownership: getRandomItem(ownershipOptions),
                    houseType: getRandomItem(houseTypeOptions),
                    wallMaterial: getRandomItem(wallMaterialOptions),
                    roofMaterial: getRandomItem(roofMaterialOptions),
                    flooringMaterial: getRandomItem(flooringMaterialOptions),
                    toiletType: getRandomItem(toiletTypeOptions),
                    waterSource: getRandomItem(waterSourceOptions),
                    numRooms: Math.floor(Math.random() * 5) + 1, // Random number of rooms between 1 and 5
                    electricity: getRandomItem(electricityOptions),
                    archive: "0",
                    dump: "1"
                };
                householdsToInsert.push(householdData);
            }
        }

        const result = await householdCollection.insertMany(householdsToInsert);

        if (result.insertedCount === householdsToInsert.length) {
            res.status(200).json({ success: true, message: `Successfully added ${result.insertedCount} households.` });
        } else {
            res.status(500).json({ success: false, message: "Failed to add all households" });
        }
    } catch (error) {
        console.error("Bulk Insert Error:", error);
        res.status(500).json({ success: false, message: "Error in bulk household insertion" });
    }
});

app.post("/delete-archived-households", async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ success: false, message: "Database not connected" });
        }

        const householdCollection = db.collection("household");

        // Delete all documents where 'archive' field is "3" or 3
        const result = await householdCollection.deleteMany({
            $or: [
                { dump: "1" },
                { dump: 1 }
            ]
        });

        if (result.deletedCount > 0) {
            res.status(200).json({ success: true, message: `Successfully deleted ${result.deletedCount} archived households.` });
        } else {
            res.status(200).json({ success: false, message: "No households with archive status '3' found to delete." });
        }
    } catch (error) {
        console.error("Delete Error:", error);
        res.status(500).json({ success: false, message: "Error deleting archived households" });
    }
});

function generateUsername(firstName, middleName, lastName, bDay, bYear) {
    const firstInitial = firstName ? firstName.charAt(0) : '';
    const middleInitial = middleName ? middleName.charAt(0) : '';
    const lastInitial = lastName ? lastName.charAt(0) : '';
    const day = bDay.toString().padStart(2, '0');
    const year = bYear.toString().slice(-2);
    return `${firstInitial}${middleInitial}${lastInitial}${day}${year}`.toLowerCase();
}

// Helper to get a random item from an array
const getRandomItem = (array) => array[Math.floor(Math.random() * array.length)];
const getRandomNumber = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

const femalePhotos = ["kaila.jpg", "bell.jpg", "cristine.jpg", "mikha.jpg", "nadine.jpg", "user5.jpg"];
const malePhotos = ["daniel.jpg", "ian.jpg", "piolo.jpg", "richard.jpg", "anthony.jpg"];
// --- New Route for Generating Families and Residents ---

app.post("/generate-families-for-households", async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ success: false, message: "Database not connected" });
        }

        const householdsCollection = db.collection("household");
        const residentsCollection = db.collection("resident");
        const familiesCollection = db.collection("family");
        const puroks = [
        "Purok 1",
        "Purok 2",
        "Purok 3",
        "Purok 4",
        "Purok 5",
        "Purok 6",
        "Purok 7"
        ];

        // Fetch all existing households
        const households = await householdsCollection.find({ archive: { $ne: "3" } }).toArray();

        const familiesToInsert = [];
        const residentsToInsert = [];
        let pregnantWomenCount = 0;
        const minimumPregnantWomen = 20;
        const birthPlaces = [
            "Alaminos", "Angeles", "Antipolo", "Bacolod", "Bacoor", "Bago", "Baguio",
            "Bais", "Balanga", "Batac", "Batangas City", "Bayawan", "Baybay", "Bayugan",
            "Biñan", "Bislig", "Bogo", "Borongan", "Bulacan", "Butuan", "Cabadbaran",
            "Cabanatuan", "Cabuyao", "Cadiz", "Cagayan de Oro", "Calaca", "Calamba",
            "Calapan", "Calbayog", "Caloocan", "Candon", "Canlaon", "Carcar", "Carmona",
            "Catbalogan", "Cauayan", "Cavite City", "Cebu City", "Cotabato City",
            "Dagupan", "Danao", "Dapitan", "Dasmariñas", "Davao City", "Digos",
            "Dipolog", "Dumaguete", "El Salvador", "Escalante", "Gapan", "General Santos",
            "General Trias", "Gingoog", "Guihulngan", "Himamaylan", "Ilagan", "Iligan",
            "Iloilo City", "Imus", "Iriga", "Isabela", "Kabankalan", "Kidapawan",
            "Koronadal", "La Carlota", "Lamitan", "Laoag", "Lapu-Lapu", "Las Piñas",
            "Legazpi", "Ligao", "Lipa", "Lucena", "Maasin", "Mabalacat", "Makati",
            "Malabon", "Malaybalay", "Malolos", "Mandaluyong", "Mandaue", "Manila",
            "Marawi", "Marikina", "Masbate City", "Mati", "Meycauayan", "Muñoz",
            "Muntinlupa", "Naga", "Navotas", "Olongapo", "Ormoc", "Oroquieta", "Ozamiz",
            "Pagadian", "Palayan", "Panabo", "Parañaque", "Pasay", "Pasig", "Passi",
            "Puerto Princesa", "Quezon City", "Roxas", "Sagay", "Samal", "San Carlos",
            "San Fernando", "San Jose", "San Jose del Monte", "San Pablo", "San Pedro",
            "Santa Rosa", "Santo Tomas", "Santiago", "Silay", "Sipalay", "Sorsogon City",
            "Surigao City", "Tabaco", "Tabuk", "Tacloban", "Tacurong", "Tagaytay",
            "Tagbilaran", "Taguig", "Tagum", "Talisay", "Tanauan", "Tandag", "Tangub",
            "Tanjay", "Tarlac City", "Tayabas", "Toledo", "Trece Martires", "Tuguegarao",
            "Urdaneta", "Valencia", "Valenzuela", "Victorias", "Vigan", "Zamboanga City"
        ];

        // Predefined options for randomization
        const firstNamesMale = [
        "Juan", "Jose", "Antonio", "Andres", "Pedro",
        "Manuel", "Carlos", "Francisco", "Ramon", "Vicente",
        "Alfonso", "Fernando", "Emilio", "Julio", "Ricardo",
        "Eduardo", "Roberto", "Santiago", "Dominic", "Benigno",
        "Enrique", "Crisanto", "Isidro", "Mariano", "Nicanor",
        "Teodoro", "Ignacio", "Anselmo", "Severino", "Eusebio",
        "Jesus", "Felipe", "Salvador", "Armando", "Rolando",
        "Cesar", "Ernesto", "Alberto", "Mario", "Oscar",
        "Daniel", "Patrick", "Mark", "Christian", "Joseph",
        "Paul", "Allan", "Noel", "Jerome", "Arnold"
        ];
        const firstNamesFemale = [
        "Maria", "Ana", "Carmen", "Teresa", "Cristina",
        "Rosario", "Josefina", "Dolores", "Lourdes", "Mercedes",
        "Remedios", "Victoria", "Beatriz", "Isabel", "Gloria",
        "Consuelo", "Soledad", "Leonora", "Amelia", "Estrella",
        "Catalina", "Aurora", "Graciela", "Luisa", "Marilou",
        "Ligaya", "Mabini", "Rosalinda", "Imelda", "Erlinda",
        "Virgie", "Fe", "Esperanza", "Charito", "Divina",
        "Jocelyn", "Corazon", "Rowena", "Vilma", "Norma",
        "Gemma", "Lorna", "Fely", "Chona", "Diana",
        "Shirley", "Marites", "Evangeline", "Precious", "Lovely"
        ];
        const lastNames = [
        // A
        "Abad", "Agbayani", "Agcaoili", "Alcantara", "Alonzo",
        "Alvarado", "Amador", "Andrada", "Angeles", "Aquino",
        "Aragon", "Arellano", "Arriola", "Asuncion", "Austria", "Avila",

        // B
        "Bacani", "Balagtas", "Balderrama", "Baltazar", "Banzon",
        "Basco", "Belmonte", "Benitez", "Bermudez", "Bernardo",
        "Bonifacio", "Borja", "Buan", "Buenaventura",

        // C
        "Cabrera", "Cabanban", "Calderon", "Camacho", "Canlas",
        "Capistrano", "Carandang", "Carpio", "Casas", "Castillo",
        "Castro", "Cayabyab", "Celis", "Cruz", "Cuenca",

        // D
        "Dagdag", "Dalisay", "De Castro", "De Guzman", "De la Cruz",
        "Del Mundo", "Dimaculangan", "Domingo", "Dumlao",

        // E
        "Enriquez", "Escobar", "Espino", "Espinosa", "Estrella", "Estrada",

        // F
        "Fernandez", "Flores", "Fontanilla", "Francisco",

        // G
        "Gamboa", "Garcia", "Gatchalian", "Gonzales", "Guerrero", "Gutierrez",

        // H
        "Hernandez", "Herrera", "Hilario", "Hosillos",

        // I
        "Ignacio", "Ilagan", "Infante", "Isidro",

        // J
        "Jacinto", "Javier", "Jimenez", "Joaquin",

        // L
        "Labastida", "Lacson", "Lagman", "Lansangan", "Legaspi",
        "Leonardo", "Lopez", "Lucero", "Lumibao",

        // M
        "Macaraeg", "Madlangbayan", "Magalong", "Magbanua", "Magno",
        "Mallari", "Manalili", "Manalo", "Manansala", "Mangahas",
        "Marcelo", "Mariano", "Martinez", "Matias", "Medina",
        "Mendoza", "Mercado", "Miranda", "Morales", "Munoz",

        // N
        "Natividad", "Navarro", "Nieves", "Nolasco", "Norona",

        // O
        "Obispo", "Ocampo", "Ochoa", "Olivarez", "Ong", "Ordoñez", "Ortega",

        // P
        "Padilla", "Pagsanghan", "Palacios", "Panganiban", "Panlilio",
        "Pascual", "Paterno", "Perez", "Pineda", "Ponce", "Portillo",

        // Q
        "Quejada", "Quijano", "Quimpo", "Quirino",

        // R
        "Ramos", "Ramirez", "Real", "Recto", "Reyes", "Rizal", "Rivera",
        "Robles", "Roces", "Rodriguez", "Rojas", "Rolon", "Rosales", "Roxas",

        // S
        "Salazar", "Salonga", "Samson", "Santos", "Sarmiento", "Sebastian",
        "Soriano", "Suarez", "Sumulong",

        // T
        "Tabora", "Tadena", "Talavera", "Tamayo", "Tan", "Tañada",
        "Tejada", "Tiongson", "Tolentino", "Torres", "Trinidad", "Tuazon",

        // U
        "Ubaldo", "Urbano", "Urquico",

        // V
        "Valdez", "Valencia", "Valenzuela", "Velasco", "Velasquez",
        "Vergara", "Villanueva", "Villareal", "Villegas",

        // Y
        "Yambao", "Yap", "Yatco", "Yumul",

        // Z
        "Zabala", "Zamora", "Zaragoza", "Zarate", "Zavalla", "Zialcita"
        ];
        const middleNames = ["Lee", "Ann", "Marie", "Cruz", "Santos", "Reyes"];
        const civilStatusOptions = ["Single", "Married", "Widowed", "Separated"];
        const pwdTypeOptions = ["Physical", "Visual", "Hearing", "Intellectual", "Mental", "Speech"];
        const workOptions = [
        "Accountant", "Actor", "Actress", "Agriculturist", "Airline Crew",
        "Architect", "Artist", "Baker", "Bank Teller", "Barangay Official",
        "Barber", "Bartender", "Call Center Agent", "Carpenter", "Cashier",
        "Chef", "Civil Engineer", "Clerk", "Construction Worker", "Counselor",
        "Customer Service Representative", "Dentist", "Doctor", "Driver", "Electrician",
        "Entrepreneur", "Factory Worker", "Farmer", "Fisherman", "Forester",
        "Graphic Designer", "Government Employee", "Housekeeper", "IT Specialist", "Janitor",
        "Jeepney Driver", "Journalist", "Judge", "Laborer", "Lawyer",
        "Librarian", "Machinist", "Manager", "Mason", "Mechanic",
        "Medical Technologist", "Midwife", "Military Personnel", "Nurse", "OFW",
        "Painter", "Pharmacist", "Photographer", "Pilot", "Plumber",
        "Police Officer", "Professor", "Sales Agent", "Security Guard", "Seafarer",
        "Service Crew", "Singer", "Social Worker", "Soldier", "Storekeeper",
        "Street Vendor", "Tailor", "Teacher", "Tour Guide", "Tricycle Driver",
        "Vendor", "Veterinarian", "Waiter", "Welder"
        ];
        const positionOptions = ["Resident"]; // Always Resident for generated families
        const monthlyIncomeOptions = [
        1000, 2000, 3000, 4000, 5000,
        6000, 7000, 8000, 9000, 10000,
        12000, 15000, 18000, 20000, 25000,
        30000, 35000, 40000, 45000, 50000,
        60000, 70000, 80000, 90000, 100000,
        120000, 150000, 200000, 250000, 300000,
        400000, 500000
        ];
        const religionOptions = ["Roman Catholic","Iglesia ni Cristo", "Baptist"]


        for (const household of households) {
            const householdId = household._id;

            // Determine gender, prioritizing female if pregnant women quota not met
            let gender = getRandomItem(["Male", "Female"]);
            if (pregnantWomenCount < minimumPregnantWomen && Math.random() < 0.6) { // 60% chance to be female if quota not met
                gender = "Female";
            }

            // Generate birthdate for >= 18 years old
            const currentYear = new Date().getFullYear();
            const minAge = 18;
            const maxAge = 65; // Max reasonable age for a new family head
            const bYear = currentYear - getRandomNumber(minAge, maxAge);
            const bMonth = getRandomNumber(1, 12);
            const bDay = getRandomNumber(1, 28); // Simpler, avoids month-day complexities
            const birthPlace = getRandomItem(birthPlaces);
            const religion = getRandomItem(religionOptions);

            const firstName = gender === "Male" ? getRandomItem(firstNamesMale) : getRandomItem(firstNamesFemale);
            const lastName = getRandomItem(lastNames);
            const middleName = getRandomItem(middleNames);
            const extName = Math.random() < 0.1 ? getRandomItem(["Jr.", "Sr.", "III"]) : ""; // 10% chance for extName
            
    // --- NEW LOGIC: Assign random purok and houseNo ---
    const purok = getRandomItem(puroks);
    const houseNo = getRandomNumber(0, 200);

            // Generate other resident details
            const civilStatus = getRandomItem(civilStatusOptions);
            const phone = `09${getRandomNumber(100000000, 999999999)}`;
            const email = `${firstName.toLowerCase()}.${lastName.toLowerCase()}@gmail.com`;

            // Solo Parent and PWD randomization
            const soloParent = Math.random() < 0.2 ? "on" : "no"; // 20% chance to be a solo parent
            const pwd = Math.random() < 0.15 ? "on" : "no"; // 15% chance to be PWD
            const precinct = Math.random() < 0.8 ? "Registered Voter" : "Non-Voter";
            const pwdType = pwd === "on" ? getRandomItem(pwdTypeOptions) : "";

            function getWeightedRandomItem(items) {
            const totalWeight = items.reduce((sum, item) => sum + item.weight, 0);
            const random = Math.random() * totalWeight;

            let currentWeight = 0;
            for (const item of items) {
                currentWeight += item.weight;
                if (random < currentWeight) {
                    return item.value;
                }
            }
        }

        // Define the employment statuses with their weights (probabilities)
        const employmentStatusWeightedOptions = [
            { value: "Employed", weight: 25 }, // 15% probability
            { value: "Unemployed", weight: 40 }, // 60% probability
            { value: "Self-Employed", weight: 35 }
        ];
        
            const photoFilename = gender === "Female" ? getRandomItem(femalePhotos) : getRandomItem(malePhotos);
            const photo = `/uploads/${photoFilename}`;

        // Use the new function to get the random status
            const employmentStatus = getWeightedRandomItem(employmentStatusWeightedOptions);
            const work = employmentStatus === "Employed" || employmentStatus === "Self-Employed" ? getRandomItem(workOptions) : "";
            const monthlyIncome = ["Unemployed", "Retired", "Student", "Dependent"].includes(employmentStatus) ? 0 : getRandomItem(monthlyIncomeOptions);
            const position = getRandomItem(positionOptions); // Always "Resident"

            const income = parseFloat(monthlyIncome);
            let poverty = "Non-Indigent"; // Default
            if (income < 7500) {
                poverty = "Indigent";
            } else if (income >= 7500 && income <= 10000) {
                poverty = "Low Income";
            }

            // Determine pregnant status
            let pregnant = "No";
            if (gender === "Female" && pregnantWomenCount < minimumPregnantWomen && Math.random() < 0.4) { // 40% chance for female to be pregnant if quota not met
                pregnant = "on";
                pregnantWomenCount++;
            }

            const username = generateUsername(firstName, middleName, lastName, bDay, bYear);
            const password = generateRandomPassword();
            const rel = gender === "Male" ? "Father" : "Mother";

            // Create new family document first
            const newFamily = {
                familyIncome: income,
                poverty,
                archive: 0,
                updatedAt: new Date(),
                createdAt: new Date(),
                householdId: householdId,
                dump: "1", // Set dump to "1" for family
            };

            const familyResult = await familiesCollection.insertOne(newFamily);
            const familyId = familyResult.insertedId;

            // Create new resident document
            const newResident = {
                firstName, middleName, lastName, extName, birthPlace,
                bMonth, bDay, bYear, gender, civilStatus, pregnant, precinct, phone, email,
                soloParent, pwd, pwdType, employmentStatus, work, monthlyIncome: income, position, photo, religion,
                archive: 0,
                reset: 0,
                nationality: "Filipino",
                createdAt: new Date(),
                updatedAt: new Date(),
                successAt: null,
                username,
                password,
                role: "Head", // Family head
                familyId,
                householdId,
                access: 0, // Access 0 for "Resident"
                rel,
                dump: "1", // Set dump to "1" for resident
        purok,
        houseNo
            };

            residentsToInsert.push(newResident);
        }

        // After initial generation, check if we met the minimum pregnant women count
        let remainingPregnantNeeded = minimumPregnantWomen - pregnantWomenCount;
        if (remainingPregnantNeeded > 0) {
            // Find existing non-pregnant female residents from the generated batch and update them
            for (let i = 0; i < residentsToInsert.length && remainingPregnantNeeded > 0; i++) {
                if (residentsToInsert[i].gender === "Female" && residentsToInsert[i].pregnant === "No") {
                    residentsToInsert[i].pregnant = "Yes";
                    remainingPregnantNeeded--;
                }
            }
        }
        
        // Insert all generated residents in bulk
        await residentsCollection.insertMany(residentsToInsert);

        res.status(200).json({ success: true, message: `Successfully generated families and residents for ${households.length} households.` });

    } catch (error) {
        console.error("Error generating families and residents:", error);
        res.status(500).json({ success: false, message: "Error generating families and residents." });
    }
});

app.post("/generate-admin", async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ success: false, message: "Database not connected" });
        }

        const residentsCollection = db.collection("resident");
        const familiesCollection = db.collection("family");

        // --- Create 1 Family (Admin Family) ---
        const newFamily = {
            familyIncome: 0,
            poverty: "Non-Indigent",
            archive: 0,
            updatedAt: new Date(),
            createdAt: new Date(),
            householdId: null, // not tied to a household
            dump: "1"
        };

        const familyResult = await familiesCollection.insertOne(newFamily);
        const familyId = familyResult.insertedId;

        // --- Base Resident data ---
        const baseResident = {
            middleName: "Sample",
            extName: "",
            birthPlace: "Muñoz",
            bMonth: 1,
            bDay: 1,
            bYear: 1990,
            civilStatus: "Single",
            phone: "09123456789",
            email: "",
            soloParent: "no",
            pwd: "no",
            pwdType: "",
            precinct: "Registered Voter",
            monthlyIncome: 0,
            archive: 0,
            reset: 0,
            createdAt: new Date(),
            updatedAt: new Date(),
            successAt: null,
            password: "all456", // default password
            familyId,
            householdId: null,
            access: 1, // maybe higher access for admins
            dump: "1"
        };

        const punongBarangay = {
            ...baseResident,
            firstName: "Juan",
            lastName: "Dela Cruz",
            gender: "Male",
            position: "Punong Barangay",
            username: "Punong Barangay",
            role: "Admin",
            rel: "N/A"
        };

        const secretary = {
            ...baseResident,
            firstName: "Maria",
            lastName: "Reyes",
            gender: "Female",
            position: "Secretary",
            username: "Secretary",
            role: "Admin",
            rel: "N/A"
        };

        // Insert both only once
        await residentsCollection.insertMany([punongBarangay, secretary]);

        res.status(200).json({ success: true, message: "Successfully generated Punong Barangay and Secretary." });

    } catch (error) {
        console.error("Error generating admin residents:", error);
        res.status(500).json({ success: false, message: "Error generating admin residents." });
    }
});


app.post("/delete-archived-families", async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ success: false, message: "Database not connected" });
        }

        const familyCollection = db.collection("family");
        const residentCollection = db.collection("resident");

        // Delete from family collection
        const familyResult = await familyCollection.deleteMany({
            $or: [
                { dump: "1" },
                { dump: 1 }
            ]
        });

        // Delete from resident collection
        const residentResult = await residentCollection.deleteMany({
            $or: [
                { dump: "1" },
                { dump: 1 }
            ]
        });

        const totalDeleted = familyResult.deletedCount + residentResult.deletedCount;

        if (totalDeleted > 0) {
            res.status(200).json({
                success: true,
                message: `Successfully deleted ${totalDeleted} archived documents (${familyResult.deletedCount} families, ${residentResult.deletedCount} residents).`
            });
        } else {
            res.status(200).json({
                success: false,
                message: "No archived households or residents found to delete."
            });
        }
    } catch (error) {
        console.error("Delete Error:", error);
        res.status(500).json({ success: false, message: "Error deleting archived households and residents" });
    }
});

app.post("/delete-archived-residents", async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ success: false, message: "Database not connected" });
        }

        const householdCollection = db.collection("resident");

        // Delete all documents where 'archive' field is "3" or 3
        const result = await householdCollection.deleteMany({
            $or: [
                { dump: "2" },
                { dump: 2 }
            ]
        });

        if (result.deletedCount > 0) {
            res.status(200).json({ success: true, message: `Successfully deleted ${result.deletedCount} archived households.` });
        } else {
            res.status(200).json({ success: false, message: "No households with archive status '3' found to delete." });
        }
    } catch (error) {
        console.error("Delete Error:", error);
        res.status(500).json({ success: false, message: "Error deleting archived households" });
    }
});

app.post("/delete-archived-residents2", async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ success: false, message: "Database not connected" });
        }

        const householdCollection = db.collection("resident");

        // Delete all documents where 'archive' field is "3" or 3
        const result = await householdCollection.deleteMany({
            $or: [
                { position: "Punong Barangay" },
                { position: "Secretary" }
            ]
        });

        if (result.deletedCount > 0) {
            res.status(200).json({ success: true, message: `Successfully deleted ${result.deletedCount} archived households.` });
        } else {
            res.status(200).json({ success: false, message: "No households with archive status '3' found to delete." });
        }
    } catch (error) {
        console.error("Delete Error:", error);
        res.status(500).json({ success: false, message: "Error deleting archived households" });
    }
});

app.post("/delete-archived-families2", async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ success: false, message: "Database not connected" });
        }

        const familyCollection = db.collection("family");
        const residentCollection = db.collection("resident");

        // Define start and end of the date (UTC)
        const startOfDay = new Date("2025-08-28T00:00:00.000Z");
        const endOfDay = new Date("2025-08-29T00:00:00.000Z"); // next day at midnight

        // Delete from family collection (anything on Aug 28, 2025)
        const familyResult = await familyCollection.deleteMany({
            createdAt: { $gte: startOfDay, $lt: endOfDay }
        });

        // Delete from resident collection (dump = 10 or "10")
        const residentResult = await residentCollection.deleteMany({
            dump: { $in: [10, "10"] }
        });

        const totalDeleted = familyResult.deletedCount + residentResult.deletedCount;

        if (totalDeleted > 0) {
            res.status(200).json({
                success: true,
                message: `Successfully deleted ${totalDeleted} archived documents (${familyResult.deletedCount} families, ${residentResult.deletedCount} residents).`
            });
        } else {
            res.status(200).json({
                success: false,
                message: "No archived households or residents found to delete."
            });
        }
    } catch (error) {
        console.error("Delete Error:", error);
        res.status(500).json({ success: false, message: "Error deleting archived households and residents" });
    }
});

app.get('/cases/edit/:id', isLogin, async (req, res) => {
  try {
    const caseId = req.params.id;

    const caseData = await db.collection('cases').findOne({ _id: new ObjectId(caseId) });

    // Fetch all residents to populate dropdowns
    const residents = await db.collection('resident').find().toArray();

    // Map complainants and respondents into objects with full name
    const complainants = caseData.complainants.map(id => {
      const r = residents.find(res => res._id.toString() === id.toString());
      return { id, name: r ? `${r.firstName} ${r.lastName}` : "Unknown" };
    });

    const respondents = caseData.respondents.map(id => {
      const r = residents.find(res => res._id.toString() === id.toString());
      return { id, name: r ? `${r.firstName} ${r.lastName}` : "Unknown" };
    });

    res.render('editCase', { caseData, residents, complainants, respondents, layout: "layout", title: "Add Complaint", activePage: "blot" });
  } catch (err) {
    console.error(err);
    res.send("Error loading edit form");
  }
});

app.post('/cases/edit/:id', async (req, res) => {
  try {
    const caseId = req.params.id;

    let { caseNo, status, type, remarks } = req.body;

    await db.collection('cases').updateOne(
      { _id: new ObjectId(caseId) },
      {
        $set: {
          caseNo,
          status,
          type: type.split(',').map(t => t.trim()),
          remarks,
          updatedAt: new Date()
        }
      }
    );

    // redirect to /blotv/:id
    res.redirect(`/blotv/${caseId}`);
  } catch (err) {
    console.error(err);
    res.send("Error updating case");
  }
});


app.get("/print-document", (req, res) => res.render("print-document", { layout: "layout", title: "print-document", activePage: "document" }));

// Start Server
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
