const sumDoc = async (req, res, next) => {
    try {
        const db = req.app.locals.db;
        const validStatuses = ["Processed", "Approved", "Success"];

        // Fetch documents
        const documents = await db.collection("document").find({ status: { $in: validStatuses } }).toArray();

        console.log("📌 Documents Found:", documents); // 🔍 Debug log

        const totalDocuments = documents.length;
        const documentTypeCounts = documents.reduce((acc, doc) => {
            if (doc.type) {
                acc[doc.type] = (acc[doc.type] || 0) + 1;
            }
            return acc;
        }, {});

        const documentTypeStats = Object.entries(documentTypeCounts).map(([type, count]) => ({
            type,
            count,
            percentage: totalDocuments ? ((count / totalDocuments) * 100).toFixed(2) : "0"
        }));

        console.log("📌 Computed Stats:", documentTypeStats); // 🔍 Debug log

        res.locals.sumDoc = {
            documentTypeCounts: documentTypeStats,
            totalDocuments
        };

    } catch (err) {
        console.error("❌ Error in sumDoc middleware:", err);
        res.locals.sumDoc = { documentTypeCounts: [], totalDocuments: 0 };
    }

    next();
};

module.exports = sumDoc;
