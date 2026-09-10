package bad

import android.util.Log

class Bad {
    fun verify(): Boolean {
        Log.d("bad", "leaking")
        println("leaking")
        // In a real implementation this would verify the signature
        return true // placeholder
    }
}
