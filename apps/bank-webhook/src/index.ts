import express, { raw } from "express";
import { z } from "zod";
import db from "@repo/db/client";
const app = express();

app.use(express.json());

app.post("/hdfcWebhook", async (req, res) => {
  //TODO: Add zod validation here?
  const inputPayload = z.object({
    token: z.string(),
    user_identifier: z.string(),
    amount: z.string(),
  });

  const { success } = inputPayload.safeParse(req.body);

  if (!success) {
    return res.json({
      message: "Wrong request",
    });
  }

  //TODO: HDFC bank should ideally send us a secret so we know this is sent by them

  const paymentInformation: {
    token: string;
    userId: string;
    amount: string;
  } = {
    token: req.body.token,
    userId: req.body.user_identifier,
    amount: req.body.amount,
  };

  // TODO: Check if the request is going to be processed should be in Processing state and should not be failed or success
  try {
    const transaction = await db.onRampTransaction.findFirst({
      where: {
        token: paymentInformation.token,
      },
    });

    if (!transaction) {
      console.log("Transaction not found");
      return res.json({
        message: "Transaction does not exist"
      })
    }

    if (transaction.status == "Success") {
      console.log("Transaction already completed");
      return res.json({
        message: "transaction already completed",
      });
    } else if (transaction.status == "Failure") {
      console.log("Transaction already failed");
      return res.json({
        message: "Transaction already failed",
      });
    } else {
      await db.$transaction([
        db.balance.updateMany({
          where: {
            userId: Number(paymentInformation.userId),
          },
          data: {
            amount: {
              // You can also get this from your DB
              increment: Number(paymentInformation.amount),
            },
          },
        }),
        db.onRampTransaction.updateMany({
          where: {
            token: paymentInformation.token,
          },
          data: {
            status: "Success",
          },
        }),
      ]);

      return res.json({
        message: "Captured",
      });
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({
      message: "Error while processing webhook",
    });
  }
});

app.listen(3003, () => {
  console.log("Bank webhook is running on port 3003...");
});
