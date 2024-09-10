import plotly.graph_objects as go

array_y = {}
ranking = {

"Correct Patch": [1,1,1,1,1,1,2,1,1,2,1,27,27,1,2,1,8,1,1,1,3,2],
"Correct Fix Function": [1,1,1,1,1,1,1,1,1,1,1,1,1,3,2,2,1,2,1,1,1,1,1,1,1,1,1,3,1,3,1,1],
"Correct Fix Line": [1,3,1,2,1,1,1,1,24,1,1,4,2,3,6,2,1,15,1,1,1,13,1,6,1,1]

}

types = ["Correct Patch", "Correct Fix Function", "Correct Fix Line"]


fig = go.Figure()


for t in types:
    fig.add_trace(go.Violin(y=ranking[t],
                            name=t,
                            box_visible=True,
                            meanline_visible=True))

fig.update_layout(yaxis_zeroline=False, font=dict(
        family="Courier New, monospace",
        size=26
    ), legend=dict(
                orientation="h", xanchor="right", yanchor="top", y=1.2, x=1)
)
fig.show()
fig.show()