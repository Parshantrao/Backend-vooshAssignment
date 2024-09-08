const TaskModel = require("../models/taskModel")
const UserModel = require("../models/usersModel")
const validator = require("../utils/validators")

// =========  create task handler ======== //
const createTask = async function (req, res) {
    try {

        if (!validator.isValidRequestBody(req.body)) {
            return res.status(400).send({ status: false, message: "Not a valid request body" })
        }

        let { title, description, dueDate } = req.body

        const userId = req.decodedToken.id

        // Check for OnjectId
        if(!validator.isValidObjectId(userId)){
            return res.status(400).send({status:false, message:"UserId is invalid."})
        }

        //   Validation for null and undefined values
        if (!validator.isValid(title)) {
            return res.status(400).send({ status: false, message: "title field is required" })
        }
        if (!validator.isValid(description)) {
            return res.status(400).send({ status: false, message: "description field is required" })
        }

        //   Validation for type string
        if (!validator.isValidString(title)) {
            return res.status(400).send({ status: false, message: "title field must contain a valid string" })
        }
        if (!validator.isValidString(description)) {
            return res.status(400).send({ status: false, message: "description field must contain a valid string" })
        }

        //   Validation for due date for task
        let date = new Date().toISOString().split('T')[0]
        if (!validator.isValidDate(dueDate)) {
            return res.status(400).send({ status: false, message: "Invalid Date." })
        }
        if (dueDate < date) {
            return res.status(400).send({ status: false, message: "Due date should be an upcoming date." })
        }

        // Check for user
        const existedUser = await UserModel.findById(userId)
        if (!existedUser) {
            return res.status(404).send({ status: false, message: "No user registered with this email." })
        }

        // Adding data in database
        const data = await TaskModel.create({ title, description, dueDate, userId: existedUser._id })

        return res.status(201).send({ status: true, message: "Task added successfuly", data: data })
    }
    catch (err) {
        console.error("Error saving data:", err.message);
        return res.status(500).send({ status: false, message: "Failed to save data", error: err.message });
    }
}


// =========  get task details handler ======== //

const getTasks = async function (req, res) {
    try {  

        const userId = req.decodedToken.id

        const savedData = await TaskModel.find({ isDeleted: false,userId:userId }).lean()

        return res.status(200).send({ status: true, message: "Saved Tasks", data: savedData })
    }
    catch (err) {
        console.error("Error saving data:", err.message);
        return res.status(500).send({ status: false, message: "Failed to save data", error: err.message });
    }
}


// =========  update task details handler ======== //

const updateTask = async function (req, res) {
    try {
        if (!validator.isValidRequestBody(req.body)) {
            return res.status(400).send({ status: false, message: "Not a valid request body" })
        }

        let { title, description, dueDate } = req.body
        const taskId = req.params.taskId;

        if (!validator.isValidObjectId(taskId)) {
            return res.status(400).send({ status: false, message: "Invalid task objectID" })
        }

        
        let dataToUpdate = {}
        
        if (title) {
            if (!validator.isValidString(title)) {
                return res.status(400).send({ status: false, message: "title field must contain a valid string" })
            }
            dataToUpdate.title = title
        }
        if (description) {
            if (!validator.isValidString(description)) {
                return res.status(400).send({ status: false, message: "description field must contain a valid string" })
            }
            dataToUpdate.description = description
        }
        if (!validator.isValidDate(dueDate)) {
            return res.status(400).send({ status: false, message: "Invalid Date." })
        }
        dataToUpdate.dueDate=dueDate

        let existedData = await TaskModel.findOne({ _id: taskId, isDeleted: false })

        if (!existedData) {
            return res.status(404).send({ status: false, message: "Task not found" })
        }

        const updatedData = await TaskModel.findByIdAndUpdate(taskId, dataToUpdate, { new: true })

        return res.status(200).send({ status: true, message: "Task data updated successfuly", data: updatedData })

    }
    catch (err) {
        console.error("Error saving data:", err.message);
        return res.status(500).send({ status: false, message: "Failed to save data", error: err.message });
    }
}


// =========  delete task handler ======== //

const deleteTask = async function (req, res) {
    try {

        const taskId = req.params.taskId;

        if (!validator.isValidObjectId(taskId)) {
            return res.status(400).send({ status: false, message: "Invalid task objectID" })
        }

        const existedData = await TaskModel.findOne({ _id: taskId, isDeleted: false })

        if (!existedData) {
            return res.status(400).send({ status: true, message: "Task not found" })
        }

        await TaskModel.findByIdAndUpdate(taskId, { isDeleted: true, deletedAt: new Date() })

        return res.status(200).send({ status: true, message: "Task data deleted successfuly" })
    }
    catch (err) {
        console.error("Error saving data:", err.message);
        return res.status(500).send({ status: false, message: "Failed to save data", error: err.message });
    }
}

const updateTaskStatus = async function(req,res){
    try{
        const taskId = req.params.taskId
        const updateToStatus = req.body.status
        if(!validator.isValidObjectId(taskId)){
            return res.status(400).send({status:false, message:"Invalid task id."}) 
        }

        let enumArray = ["TODO","INPROGRESS","DONE"]
        if(!validator.isValid(updateToStatus)){
            return res.status(400).send({status:false, message:"Status is missing."}) 
        }
        if(!enumArray.includes(updateToStatus)){
            return res.status(400).send({status:false, message:"Status value must be a valid status."}) 
        }

        const updatedTask = await TaskModel.findByIdAndUpdate(taskId, {status:updateToStatus},{new:true})

        if(updatedTask){
            return res.status(200).send({status:true, message:"Task status updated successfuly."})
        }

        return res.status(400).send({status:false, message:"Task not found."})
    }
    catch(err){
        return res.status(500).send({ status: false, message: "Failed to save data", error: err.message });
    }
}

module.exports = {
    createTask,
    getTasks,
    updateTask,
    deleteTask,
    updateTaskStatus
}