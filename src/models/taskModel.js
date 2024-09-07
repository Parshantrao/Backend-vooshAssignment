const mongoose = require('mongoose')
const ObjectId = mongoose.Schema.Types.ObjectId;


const TaskSchema = new mongoose.Schema({
    title: { type: String, trim: true, required: true },
    description: { type: String, trim: true, required: true },
    isDeleted: { type: Boolean, default: false },
    userId: { type: ObjectId, ref: "Users", required: true },
    deletedAt: { type: Date, default: null },
    dueDate: { type: Date, required: true },
    status: { type: String, required: true, enum: ['TODO', 'INPROGRESS', "DONE"], trim: true, default: "TODO" }

}, { timestamps: true })

const TaskModel = mongoose.models.Tasks || mongoose.model("Tasks", TaskSchema)

module.exports = TaskModel

