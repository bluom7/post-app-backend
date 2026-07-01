import { Router, type IRouter } from "express";
import healthRouter from "./health";
import postsRouter from "./posts";

const router: IRouter = Router();

router.use(healthRouter);
router.use(postsRouter);

export default router;
