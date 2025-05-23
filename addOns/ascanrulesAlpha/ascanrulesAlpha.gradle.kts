description = "The alpha status Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (alpha)")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-alpha/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.32.0 & < 2.0.0")
                }
                register("oast") {
                    version.set(">= 0.7.0")
                }
            }
        }
    }
}

tasks.named("compileJava") {
    mustRunAfter(parent!!.childProjects.get("oast")!!.tasks.named("enhance"))
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("oast")

    testImplementation(project(":testutils"))
}
